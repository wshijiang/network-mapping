//! C2 management interface candidates from HTML already collected by the scanner.

use super::{
    Product,
    rules::{Context, RuleSet},
};
use reqwest::Url;
use serde_json::Value;

const MAX_HTML_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 10;
const MAX_URL_BYTES: usize = 2048;

fn header<'a>(response: &'a Value, name: &str) -> Option<&'a str> {
    let value = &response["headers"][name];
    value
        .as_str()
        .or_else(|| value.as_array().filter(|values| values.len() == 1)?[0].as_str())
}

fn parse_url(text: &str) -> Option<Url> {
    if text.len() > MAX_URL_BYTES {
        return None;
    }
    Url::parse(text).ok()
}

fn root_request_url(response: &Value) -> Option<Url> {
    let value = &response["request"]["url"];
    let url = if let Some(text) = value.as_str() {
        parse_url(text)?
    } else {
        if value["path"] != "/"
            || value["raw_query"]
                .as_str()
                .is_some_and(|query| !query.is_empty())
        {
            return None;
        }
        let scheme = value["scheme"].as_str()?;
        let authority = value["host"].as_str()?;
        parse_url(&format!("{scheme}://{authority}/"))?
    };
    (url.has_host()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}

fn sni(response: &Value) -> Option<&str> {
    response
        .pointer("/request/tls_log/handshake_log/client_hello/server_name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn same_origin_landing<'a>(
    evidence: &'a [Value],
    response: &Value,
    module: &str,
) -> Option<(usize, &'a Value)> {
    let origin = root_request_url(response).filter(|url| url.scheme() == module)?;
    let location = header(response, "location")
        .filter(|value| !value.is_empty() && value.len() <= MAX_URL_BYTES)?;
    let mut first_hop = origin.join(location).ok()?;
    first_hop.set_fragment(None);
    let expected_origin = origin.origin();
    let same_origin = |url: &Url| {
        url.username().is_empty() && url.password().is_none() && url.origin() == expected_origin
    };
    if let Some(host) = response["request"]["host"]
        .as_str()
        .filter(|host| !host.is_empty())
        && !parse_url(&format!("{module}://{host}/")).is_some_and(|url| {
            url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && same_origin(&url)
        })
    {
        return None;
    }
    if sni(response).is_some_and(|name| {
        !origin
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(name))
    }) {
        return None;
    }
    evidence
        .iter()
        .take(64)
        .enumerate()
        .find_map(|(index, item)| {
            if item["module"] != "web_assets"
                || item["status"] != "success"
                || item["truncated"] == true
            {
                return None;
            }
            let landing = &item["result"]["landing"];
            let redirects = landing["redirects"].as_array()?;
            let actual_first = parse_url(redirects.first()?.as_str()?)?;
            (landing["status_code"] == 200
                && redirects.len() <= MAX_REDIRECTS
                && actual_first == first_hop
                && redirects.iter().all(|hop| {
                    hop.as_str()
                        .and_then(parse_url)
                        .is_some_and(|url| same_origin(&url))
                })
                && redirects.last() == Some(&landing["url"]))
            .then_some((index, landing))
        })
}

pub(super) fn candidate(
    evidence: &[Value],
    index: usize,
    module: &str,
    response: &Value,
    path: &str,
    rules: &RuleSet,
) -> (Vec<Product>, bool) {
    let item = &evidence[index];
    let code = response["status_code"].as_u64();
    let (page, probe, field_path) = if item["truncated"] == true {
        return (Vec::new(), true);
    } else if code.is_some_and(|code| (300..400).contains(&code)) {
        let Some((index, landing)) = same_origin_landing(evidence, response, module) else {
            return (Vec::new(), false);
        };
        (
            landing,
            "web_assets",
            format!("/evidence/{index}/result/landing/body"),
        )
    } else {
        if code != Some(200) || item["status"] != "success" {
            return (Vec::new(), false);
        }
        if !header(response, "content_type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
        }) {
            return (Vec::new(), false);
        }
        (
            response,
            module,
            format!("/evidence/{index}/result{path}/body"),
        )
    };
    let Some(body) = page["body"].as_str().filter(|body| {
        page["body_truncated"] != true && !body.trim().is_empty() && body.len() <= MAX_HTML_BYTES
    }) else {
        return (Vec::new(), true);
    };
    let context = Context {
        probe,
        field_path: &field_path,
        http_host: response
            .pointer("/request/host")
            .or_else(|| response.pointer("/request/url/host"))
            .and_then(Value::as_str),
        sni: if probe == "https" {
            sni(response)
        } else {
            None
        },
    };
    (rules.http_products(body, &context), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_products::{infer, ruleset_stamp, view};
    use serde_json::json;

    fn mythic(bundle: &str) -> String {
        format!(
            r#"<!doctype html><html><head><title>Mythic</title>
            <link rel="manifest" href="/new/manifest.json"><script src="{bundle}"></script>
            </head><body><div id="root"></div></body></html>"#
        )
    }

    const STARKILLER: &str = r#"<!doctype html><html><head><title>Starkiller</title>
        <script type="module" src="/assets/index-test.js"></script></head><body>
        <noscript><strong>We're sorry but starkiller doesn't work properly without
        JavaScript enabled.</strong></noscript><div id="app"></div></body></html>"#;

    fn observation(body: &str) -> Value {
        json!({"schema_version":2,"evidence":[{"module":"http","status":"success","result":{
            "response":{"status_code":200,"headers":{"content_type":["text/html; charset=utf-8"]},"body":body}
        }}]})
    }

    #[test]
    fn management_pages_report_only_the_observed_component_with_traceable_evidence() {
        let cases = [
            (
                mythic("/new/static/js/main.12fdaefe.js"),
                "mythic",
                "Web UI",
            ),
            (
                mythic("/new/static/js/main.0f0a7eed.js"),
                "mythic",
                "Web UI",
            ),
            (STARKILLER.into(), "empire", "Starkiller"),
        ];
        for (body, id, component) in cases {
            let data = observation(&body);
            let result = infer(Some(&data), 1200, None);
            let product = &result.products[0];
            assert_eq!(result.products.len(), 1);
            assert_eq!(product.id, id);
            assert_eq!(product.component.as_deref(), Some(component));
            assert_eq!(product.assessment, "suspected");
            assert!(product.version.is_none());
            assert_eq!(product.basis, "http_management_fingerprint");
            assert_eq!(result.product_identification.status, "suspected");
            assert_eq!(
                result.product_identification.ruleset_revision,
                ruleset_stamp().revision
            );
            let evidence = &product.evidence[0];
            assert_eq!(
                evidence.detection_method.as_deref(),
                Some("http_fingerprint")
            );
            assert_eq!(data.pointer(&evidence.field_path), Some(&json!(body)));
        }
    }

    #[test]
    fn generic_incomplete_and_conflicting_pages_do_not_identify_a_product() {
        let cases = [
            "<title>Mythic</title><body>Mythic login</body>".into(),
            mythic("/new/static/js/main.js"),
            mythic("//other.example/new/static/js/main.12fdaefe.js"),
            mythic("/new/static/js/main.12fdaefe.js").replace(
                "<title>Mythic</title>",
                "<title>Mythic</title><title>Other</title>",
            ),
            STARKILLER.replace("starkiller doesn't", "this app doesn't"),
            STARKILLER.replace(
                "/assets/index-test.js",
                "//other.example/assets/index-test.js",
            ),
            STARKILLER.replace("<head>", "<head><base href='https://other.example/'>"),
        ];
        for body in cases {
            assert!(
                infer(Some(&observation(&body)), 1, None)
                    .products
                    .is_empty()
            );
        }
        for (field, value) in [
            ("body_truncated", json!(true)),
            ("status_code", json!(404)),
            ("headers", json!({"content_type":"text/plain"})),
        ] {
            let mut data = observation(STARKILLER);
            data["evidence"][0]["result"]["response"][field] = value;
            let result = infer(Some(&data), 1, None);
            assert!(result.products.is_empty());
            if field == "body_truncated" {
                assert_eq!(result.product_identification.coverage, "partial");
            }
        }
        let oversized = format!("{STARKILLER}{}", " ".repeat(MAX_HTML_BYTES));
        let result = infer(Some(&observation(&oversized)), 1, None);
        assert!(result.products.is_empty());
        assert_eq!(result.product_identification.coverage, "partial");
    }

    #[test]
    fn recorded_landing_is_used_only_with_a_consistent_same_origin_redirect_chain() {
        let mut data = json!({"schema_version":2,"evidence":[
            {"module":"https","status":"success","result":{
                "redirect_response_chain":[{"status_code":302,"headers":{"location":["/new/"]},
                    "request":{"url":{"scheme":"https","host":"192.0.2.1:8443","path":"/"},"host":"192.0.2.1:8443"}}],
                "response":{"status_code":200,"headers":{"content_type":"text/html"},"body":STARKILLER}}},
            {"module":"web_assets","status":"success","result":{"landing":{
                "status_code":200,"redirects":["https://192.0.2.1:8443/new/"],"url":"https://192.0.2.1:8443/new/",
                "body":mythic("/new/static/js/main.12fdaefe.js"), "body_truncated":false}}}
        ]});
        let inferred = infer(Some(&data), 1200, None);
        assert_eq!(inferred.products.len(), 1);
        assert_eq!(inferred.products[0].id, "mythic");
        let evidence = &inferred.products[0].evidence[0];
        assert_eq!(evidence.probe, "web_assets");
        assert_eq!(evidence.field_path, "/evidence/1/result/landing/body");
        assert_eq!(evidence.http_host.as_deref(), Some("192.0.2.1:8443"));

        for hop in [
            "https://unrelated.example:8443/new/",
            "https://192.0.2.1/new/",
            "http://192.0.2.1:8443/new/",
        ] {
            let mut foreign = data.clone();
            let landing = &mut foreign["evidence"][1]["result"]["landing"];
            landing["redirects"] = json!(["https://192.0.2.1:8443/new/", hop, landing["url"]]);
            assert!(infer(Some(&foreign), 1200, None).products.is_empty());
        }
        data["evidence"][0]["result"]["redirect_response_chain"][0]["request"]["tls_log"]["handshake_log"]
            ["client_hello"]["server_name"] = json!("other-vhost.example");
        assert!(infer(Some(&data), 1200, None).products.is_empty());
    }

    #[test]
    fn v4_replay_uses_only_the_original_service_observation_and_time() {
        let source = json!({
            "data": observation(STARKILLER),
            "service_observation_ref": {"id":"original"},
            "products": [],
            "product_identification": {"status":"not_matched","coverage":"complete","ruleset_revision":4,
                "observed_at":1200,"stale":false,"observation_ref":{"id":"original"}}
        });
        let updated = view(&source, 1200, true);
        assert_eq!(updated.products[0].id, "empire");
        assert_eq!(updated.product_identification.observed_at, 1200);
        assert_eq!(
            updated.product_identification.observation_ref,
            Some(json!({"id":"original"}))
        );
        assert!(!updated.product_identification.stale);
        let port_only = view(&source, 1300, false);
        assert!(port_only.products.is_empty());
        assert_eq!(port_only.product_identification.observed_at, 1200);
        assert!(port_only.product_identification.stale);
    }
}
