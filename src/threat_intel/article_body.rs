//! Publisher-independent extraction of static article HTML. No script execution,
//! remote schema lookups, or whole-page fallback for challenge/index pages.
use super::*;
use scraper::{Html, Selector};

pub(super) fn extract(data: &[u8], preferred: Option<&str>) -> Result<(String, Value)> {
    if data.len() > 2 * 1024 * 1024 {
        return Err(Error::bad("intel_article_too_large"));
    }
    let input = std::str::from_utf8(data).map_err(|_| Error::bad("intel_article_not_utf8"))?;
    let html = Html::parse_document(input);
    let title = Selector::parse("title").expect("static selector");
    let challenge =
        Selector::parse("#challenge-form, #cf-challenge-running, #cf-please-wait, #px-captcha")
            .expect("static selector");
    let blocked = html.select(&challenge).next().is_some()
        || html.select(&title).any(|node| {
            let title = node.text().collect::<String>().trim().to_ascii_lowercase();
            [
                "just a moment",
                "access denied",
                "attention required",
                "robot check",
                "security verification",
            ]
            .iter()
            .any(|prefix| title.starts_with(prefix))
        });
    if blocked {
        return Err(Error::bad("intel_article_body_missing").context(json!({
            "selector":preferred.unwrap_or("generic_article"),"html_bytes":data.len(),"reason":"challenge_page"
        })));
    }
    let selectors = [
        preferred.unwrap_or("[itemprop='articleBody']"),
        "[itemprop='articleBody'], .article-body, .article__body, .article-content, .entry-content, .post-content, .post-body, .story-body, .story-content, .entry-body, .blog-post-content, .blog-content, .td-post-content, #article-body, #article-content",
        "article",
    ];
    let mut found = false;
    for root in selectors {
        if let Some(body) = candidate(&html, root, false, &mut found)? {
            return Ok((
                body,
                json!({"method":"remote_html","selector":root,"extractor":"generic-v1"}),
            ));
        }
    }
    // A typed Article's explicit body is useful on sites that hydrate their DOM
    // in JavaScript. Descriptions, summaries, and arbitrary script data are not bodies.
    let scripts = Selector::parse("script[type='application/ld+json']").expect("static selector");
    for script in html.select(&scripts).take(32) {
        if let Ok(value) = serde_json::from_str::<Value>(&script.text().collect::<String>())
            && let Some(body) = structured_body(&value, 0)?
        {
            return Ok((
                body,
                json!({"method":"remote_html","selector":"json_ld:articleBody","extractor":"generic-v1"}),
            ));
        }
    }
    for (root, heuristic) in [
        ("main, [role='main']", false),
        (
            "#content, #main-content, .content, .content-body, section, div",
            true,
        ),
    ] {
        if let Some(body) = candidate(&html, root, heuristic, &mut found)? {
            return Ok((
                body,
                json!({"method":"remote_html","selector":root,"extractor":"generic-v1"}),
            ));
        }
    }
    Err(Error::bad("intel_article_body_missing").context(json!({
        "selector":preferred.unwrap_or("generic_article"),"html_bytes":data.len(),
        "reason":if found {"no_valid_article_candidate"} else {"selector_not_found"}
    })))
}

fn candidate(html: &Html, root: &str, heuristic: bool, found: &mut bool) -> Result<Option<String>> {
    let selector = Selector::parse(root).expect("static selector");
    let links = Selector::parse("a").expect("static selector");
    let paragraphs = Selector::parse("p, pre, blockquote, table").expect("static selector");
    let mut best: Option<(usize, String)> = None;
    for node in html.select(&selector).take(128) {
        *found = true;
        let text = match parse::article_element_text(node) {
            Err(error) if heuristic && error.code == "intel_article_too_large" => continue,
            result => result?,
        };
        if text.len() < if heuristic { 200 } else { 40 } {
            continue;
        }
        if text.len() < 2000
            && [
                "verify you are human",
                "checking your browser",
                "enable javascript and cookies",
                "complete the security check",
            ]
            .iter()
            .any(|phrase| text.to_ascii_lowercase().contains(phrase))
        {
            continue;
        }
        let link_bytes = node
            .select(&links)
            .map(parse::article_element_text)
            .collect::<Result<Vec<_>>>()?
            .iter()
            .map(String::len)
            .sum::<usize>();
        if link_bytes.saturating_mul(2) > text.len() {
            continue;
        }
        if heuristic {
            let mut blocks = 0;
            let mut body_bytes = 0;
            for block in node.select(&paragraphs).take(256) {
                let text = parse::article_element_text(block)?;
                if text.len() >= 40 {
                    blocks += 1;
                    body_bytes += text.len();
                }
            }
            if blocks < 2 || body_bytes.saturating_mul(2) < text.len() {
                continue;
            }
        }
        let score = text.len().saturating_sub(link_bytes);
        if best.as_ref().is_none_or(|(current, _)| score > *current) {
            best = Some((score, text));
        }
    }
    Ok(best.map(|(_, body)| body))
}

fn structured_body(value: &Value, depth: usize) -> Result<Option<String>> {
    if depth > 8 {
        return Ok(None);
    }
    if let Some(values) = value.as_array() {
        for value in values.iter().take(128) {
            if let Some(body) = structured_body(value, depth + 1)? {
                return Ok(Some(body));
            }
        }
    }
    let article_type = |value: &Value| {
        value.as_str().is_some_and(|kind| {
            matches!(
                kind.rsplit(['/', '#']).next().unwrap_or(kind),
                "Article"
                    | "NewsArticle"
                    | "BlogPosting"
                    | "TechArticle"
                    | "Report"
                    | "AnalysisNewsArticle"
                    | "ScholarlyArticle"
            )
        })
    };
    if value.get("@type").is_some_and(|kind| {
        article_type(kind)
            || kind
                .as_array()
                .is_some_and(|types| types.iter().any(article_type))
    }) && let Some(body) = value.get("articleBody").and_then(Value::as_str)
    {
        let fragment = Html::parse_fragment(body);
        let body = parse::article_element_text(fragment.root_element())?;
        if body.len() >= 40 {
            return Ok(Some(body));
        }
    }
    for key in ["@graph", "mainEntity"] {
        if let Some(value) = value.get(key)
            && let Some(body) = structured_body(value, depth + 1)?
        {
            return Ok(Some(body));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "The researchers identified evil.example as malicious command and control infrastructure used in the reported campaign.";

    #[test]
    fn extracts_common_publisher_layouts_without_domain_specific_rules() {
        for root in [
            "article",
            "main",
            "div class='entry-content'",
            "div class='post-content'",
            "div class='article-body'",
            "div itemprop='articleBody'",
            "section role='main'",
        ] {
            let tag = root.split_whitespace().next().unwrap();
            let html = format!(
                "<html><body><nav>navigation.example</nav><{root}><header>header.example</header><p>{REPORT}</p><aside>sidebar.example</aside><div class='related-articles'>related.example</div><p style='display: none'>hidden.example</p><script>script.example</script><footer>footer.example</footer></{tag}></body></html>"
            );
            let (body, metadata) = articles::body_snapshot(
                html.as_bytes(),
                "https://any-publisher.example/report",
                "",
            )
            .unwrap();
            assert!(body.contains(REPORT), "{root}");
            for excluded in [
                "navigation.example",
                "header.example",
                "sidebar.example",
                "related.example",
                "hidden.example",
                "script.example",
                "footer.example",
            ] {
                assert!(!body.contains(excluded), "{root}: {excluded}");
            }
            assert_eq!(metadata["extractor"], "generic-v1");
        }
    }

    #[test]
    fn selects_full_article_after_teasers_and_preserves_inline_iocs_and_tables() {
        let html = format!(
            "<article><a href='/story'>A long linked preview that should not be used as the full report content.</a></article><article><p>{REPORT}</p><p>Infrastructure:\n evil.<span>example</span> is the malicious domain.</p>Outside paragraph.<a>Inline reference.</a><table><tr><td>AS64496</td>\n<td>malicious DNS</td></tr></table></article>"
        );
        let (body, _) = extract(html.as_bytes(), None).unwrap();
        assert!(body.contains("Infrastructure: evil.example is the malicious domain"));
        assert!(body.contains("domain.\nOutside paragraph.Inline reference."));
        assert!(body.contains("AS64496 | malicious DNS"));
        assert!(!body.contains("linked preview"));
    }

    #[test]
    fn extracts_typed_json_ld_article_bodies_but_never_descriptions_or_arbitrary_scripts() {
        let value = json!({"@graph":[{"@type":"Organization","description":"organization.example"},{"@type":["Thing","https://schema.org/NewsArticle"],"articleBody":REPORT}]});
        let html =
            format!("<div id='app'></div><script type='application/ld+json'>{value}</script>");
        let (body, metadata) = extract(html.as_bytes(), None).unwrap();
        assert_eq!(body, REPORT);
        assert_eq!(metadata["selector"], "json_ld:articleBody");
        for value in [
            json!({"articleBody":REPORT}),
            json!({"@type":"Organization","articleBody":REPORT}),
            json!({"@type":"Article","description":REPORT}),
        ] {
            let html = format!("<script type='application/ld+json'>{value}</script>");
            assert!(extract(html.as_bytes(), None).is_err());
        }
        let challenge = format!(
            "<title>Just a moment...</title><script type='application/ld+json'>{value}</script>"
        );
        assert_eq!(
            extract(challenge.as_bytes(), None).unwrap_err().diagnostic["reason"],
            "challenge_page"
        );
    }

    #[test]
    fn uses_paragraph_density_for_unlabelled_content_and_rejects_navigation_and_challenges() {
        let html = format!(
            "<nav>navigation.example</nav><div id='custom-report'><p>{REPORT}</p><p>{REPORT}</p></div>"
        );
        let (body, _) = extract(html.as_bytes(), None).unwrap();
        assert!(body.contains(REPORT));
        assert!(!body.contains("navigation.example"));
        for html in [
            "<main>Please verify you are human before reading this report.</main>",
            "<main><a href='/'>A sufficiently long linked menu entry with no actual report or original article body.</a></main>",
            "<div>Text without article structure must not be used as an entire page body snapshot even when it is long.</div>",
        ] {
            assert!(extract(html.as_bytes(), None).is_err());
        }
        let oversized = format!("<article><p>{}</p></article>", "x".repeat(MAX_ARTICLE + 1));
        assert_eq!(
            extract(oversized.as_bytes(), None).unwrap_err().code,
            "intel_article_too_large"
        );
    }

    #[test]
    fn publisher_preference_falls_back_to_generic_extraction_when_markup_changes() {
        let html = format!("<div class='entry-content'><p>{REPORT}</p></div>");
        let (body, metadata) = articles::body_snapshot(
            html.as_bytes(),
            "https://www.welivesecurity.com/en/report",
            "",
        )
        .unwrap();
        assert!(body.contains(REPORT));
        assert_ne!(metadata["selector"], ".article-body");
    }
}
