//! A deliberately small, validated HTML dialect shared by delivery and preview.
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tera::{Context, Tera};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub format: String,
    pub title_template: String,
    pub body_template: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rendered {
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
    pub payload: Value,
}

pub fn default_source() -> Source {
    Source {
        format: "text".into(),
        title_template: "[{{ system_name }}] {{ title }}".into(),
        body_template: "级别：{{ severity }}\n{{ body }}".into(),
    }
}

pub fn event_default_source(event: &str) -> Source {
    let Some(mail) =
        super::template_context::key(event).and_then(crate::mail_template::builtin_source)
    else {
        return default_source();
    };
    let body = if event.starts_with("report.") {
        include_str!("../../templates/notification/report.html").to_owned()
    } else {
        let text = mail.text_template.replace("此邮件", "此通知");
        let (heading, rest) = text.split_once('\n').unwrap_or((&text, ""));
        format!("<b>{heading}</b>\n{rest}")
    };
    Source {
        format: "html".into(),
        title_template: mail.subject_template,
        body_template: body,
    }
}

pub fn context(
    event: &str,
    title: &str,
    body: &str,
    severity: &str,
    id: &str,
    at: &str,
) -> Context {
    // Legacy summary variables remain available alongside the shared event-specific mail fields.
    let mut c = Context::new();
    for (key, value) in [
        ("system_name", "Network Mapping"),
        ("title", title),
        ("body", body),
        ("severity", severity),
        ("event_type", event),
        ("event_id", id),
        ("occurred_at", at),
    ] {
        c.insert(key, value);
    }
    c
}

pub fn sample_context(event: &str) -> Context {
    let (title, body) = match event {
        "user.login" => ("用户登录成功", "用户 demo 已完成登录。"),
        "scanner.offline" => (
            "Scanner 掉线",
            "扫描器：示例节点\n最后心跳：2026-01-01 08:00:00 UTC",
        ),
        "scanner.recovered" => ("Scanner 恢复连接", "扫描器：示例节点\n节点已恢复连接。"),
        "report.weekly" => ("周报已生成", "报告周期：示例周期\n请登录平台报告中心查看。"),
        "report.monthly" => ("月报已生成", "报告周期：示例周期\n请登录平台报告中心查看。"),
        _ => ("系统健康告警", "告警类型：慢请求\n详情：示例告警内容。"),
    };
    let mut context = context(
        event,
        title,
        body,
        "warning",
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01 08:00:00 UTC",
    );
    if let Some(key) = super::template_context::key(event)
        && let Ok(mail) = crate::mail_template::sample_context(key)
    {
        context.extend(mail);
    }
    if event == "scanner.recovered" {
        context.insert("event_label", "恢复");
    }
    context
}

/// Check both severity branches before accepting a template; keep the warning preview stable.
pub fn validate_source(provider: &str, source: &Source, event: &str) -> Result<Rendered> {
    let mut context = sample_context(event);
    let preview = render(provider, source, &context)?;
    context.insert("severity", "critical");
    render(provider, source, &context)?;
    Ok(preview)
}

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn decode(s: &str) -> Result<String> {
    let mut result = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        result.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let end = rest
            .find(';')
            .filter(|n| *n <= 12)
            .ok_or_else(|| Error::bad("HTML 中的 & 必须转义为 &amp;"))?;
        let entity = &rest[..end];
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    entity.strip_prefix('#').and_then(|n| n.parse().ok())
                };
                code.and_then(char::from_u32)
                    .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
                    .ok_or_else(|| Error::bad("不支持的 HTML 实体"))?
            }
        };
        result.push(c);
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Ok(result)
}

#[derive(Clone)]
struct Tag {
    name: String,
    href: Option<String>,
    card_content: String,
}

fn tag(value: &str, provider: &str) -> Result<Tag> {
    let (name, attrs) = value.split_once(char::is_whitespace).unwrap_or((value, ""));
    let name = match name {
        "strong" => "b",
        "em" => "i",
        "ins" => "u",
        "strike" | "del" => "s",
        x => x,
    };
    let allowed = matches!(name, "b" | "i" | "u" | "s" | "a")
        || (provider == "telegram" && matches!(name, "code" | "pre" | "blockquote" | "tg-spoiler"));
    if !allowed {
        return Err(Error::bad(
            "含不支持的 HTML 标签；飞书仅支持 b/i/u/s/a，Telegram 另支持 code/pre/blockquote/tg-spoiler",
        ));
    }
    let attrs = attrs.trim();
    let href = if name == "a" {
        let raw = attrs
            .strip_prefix("href=")
            .ok_or_else(|| Error::bad("链接必须使用 <a href=\"https://…\">，不支持其他属性"))?;
        let q = raw
            .chars()
            .next()
            .filter(|q| matches!(q, '\'' | '"'))
            .ok_or_else(|| Error::bad("链接地址必须使用引号"))?;
        if raw.len() < 2 || !raw.ends_with(q) || raw[1..raw.len() - 1].contains(q) {
            return Err(Error::bad("链接属性无效"));
        }
        let url = decode(&raw[1..raw.len() - 1])?;
        let parsed = reqwest::Url::parse(&url)
            .map_err(|_| Error::bad("链接必须是有效的 HTTP/HTTPS 地址"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(Error::bad("链接仅支持不含凭据的 HTTP/HTTPS 地址"));
        }
        Some(url)
    } else {
        if !attrs.is_empty() {
            return Err(Error::bad("不支持 CSS、class 或其他 HTML 属性"));
        }
        None
    };
    Ok(Tag {
        name: name.into(),
        href,
        card_content: String::new(),
    })
}

/// Escape literal content before embedding it in Feishu card Markdown.
fn card_text(input: &str) -> String {
    let mut escaped = String::new();
    for character in input.chars() {
        if character.is_ascii_punctuation() {
            escaped.push_str(&format!("&#{};", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn card_link(url: &str) -> String {
    let mut escaped = String::new();
    for character in url.chars() {
        if character.is_ascii_whitespace() || "()<>\"'\\[]".contains(character) {
            escaped.push_str(&format!("%{:02X}", u32::from(character)));
        } else if character == '&' {
            escaped.push_str("&amp;");
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn card_wrap(input: &str, prefix: &str, suffix: &str) -> String {
    input
        .split("<br>")
        .map(|line| {
            let content = line.trim();
            if content.is_empty() {
                return line.to_owned();
            }
            format!(
                "{}{prefix}{content}{suffix}{}",
                &line[..line.len() - line.trim_start().len()],
                &line[line.trim_end().len()..]
            )
        })
        .collect::<Vec<_>>()
        .join("<br>")
}

fn fragment(input: &str, provider: &str) -> Result<(String, String, String)> {
    let mut stack: Vec<Tag> = Vec::new();
    let mut html = String::new();
    let mut plain = String::new();
    let mut markdown = String::new();
    let mut rest = input;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('<') {
            let end = after
                .find('>')
                .ok_or_else(|| Error::bad("HTML 标签未闭合"))?;
            let raw = &after[..end];
            if let Some(close) = raw.strip_prefix('/') {
                let closing = tag(close, provider).or_else(|_| {
                    // Closing a tags have no href.
                    if close == "a" {
                        Ok(Tag {
                            name: "a".into(),
                            href: None,
                            card_content: String::new(),
                        })
                    } else {
                        Err(Error::bad("HTML 结束标签无效"))
                    }
                })?;
                let opened = stack
                    .pop()
                    .ok_or_else(|| Error::bad("HTML 标签嵌套不匹配"))?;
                if opened.name != closing.name {
                    return Err(Error::bad("HTML 标签嵌套不匹配"));
                }
                let content = opened.card_content;
                let content = if let Some(url) = &opened.href {
                    card_wrap(&content, "[", &format!("]({})", card_link(url)))
                } else if stack.iter().any(|tag| tag.name == opened.name) {
                    content
                } else {
                    match opened.name.as_str() {
                        "b" => card_wrap(&content, "**", "**"),
                        "i" => card_wrap(&content, "*", "*"),
                        "s" => card_wrap(&content, "~~", "~~"),
                        _ => content,
                    }
                };
                stack
                    .last_mut()
                    .map(|tag| &mut tag.card_content)
                    .unwrap_or(&mut markdown)
                    .push_str(&content);
                if provider != "feishu" || opened.name != "u" {
                    html.push_str(&format!("</{}>", opened.name));
                }
            } else {
                let opened = tag(raw, provider)?;
                if stack.len() >= 16 {
                    return Err(Error::bad("HTML 嵌套不能超过 16 层"));
                }
                if opened.name == "a" && stack.iter().any(|t| t.name == "a") {
                    return Err(Error::bad("链接不能嵌套"));
                }
                if provider == "telegram"
                    && (matches!(opened.name.as_str(), "code" | "pre" | "blockquote")
                        && !stack.is_empty()
                        || stack
                            .iter()
                            .any(|t| matches!(t.name.as_str(), "code" | "pre" | "blockquote")))
                {
                    return Err(Error::bad(
                        "code/pre/blockquote 在此编辑器中须单独使用，不能嵌套其他标签",
                    ));
                }
                if provider != "feishu" || opened.name != "u" {
                    html.push_str(&format!(
                        "<{}{}>",
                        opened.name,
                        opened
                            .href
                            .as_ref()
                            .map(|u| format!(" href=\"{}\"", escape(u)))
                            .unwrap_or_default()
                    ));
                }
                stack.push(opened);
            }
            rest = &after[end + 1..];
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            let text = decode(&rest[..end])?;
            plain.push_str(&text);
            html.push_str(&escape(&text));
            stack
                .last_mut()
                .map(|tag| &mut tag.card_content)
                .unwrap_or(&mut markdown)
                .push_str(&card_text(&text).replace('\n', "<br>"));
            rest = &rest[end..];
        }
    }
    if !stack.is_empty() {
        return Err(Error::bad("HTML 标签未闭合"));
    }
    Ok((html, plain, markdown))
}

pub fn render(provider: &str, source: &Source, c: &Context) -> Result<Rendered> {
    if !matches!(provider, "feishu" | "telegram")
        || !(matches!(source.format.as_str(), "text" | "html")
            || (provider == "telegram" && source.format == "rich_html"))
    {
        return Err(Error::bad("不支持的渠道或模板格式"));
    }
    if source.title_template.trim().is_empty()
        || source.title_template.chars().count() > 500
        || source.body_template.trim().is_empty()
        || source.body_template.len() > 12 * 1024
    {
        return Err(Error::bad("标题须为 1–500 字符，正文须为 1–12 KiB"));
    }
    let mut tera = Tera::default();
    let body_name = if source.format != "text" {
        "body.html"
    } else {
        "body.txt"
    };
    tera.add_raw_templates([
        ("title.txt", source.title_template.as_str()),
        (body_name, source.body_template.as_str()),
    ])
    .map_err(|_| Error::bad("模板语法无效"))?;
    let subject = tera
        .render("title.txt", c)
        .map_err(|_| Error::bad("标题模板渲染失败，请检查变量"))?;
    if subject.trim().is_empty() || subject.chars().count() > 200 || subject.contains(['\r', '\n'])
    {
        return Err(Error::bad("渲染后的标题须为 1–200 字符且不能换行"));
    }
    let body = tera
        .render(body_name, c)
        .map_err(|_| Error::bad("正文模板渲染失败，请检查变量"))?;
    if body.len() > 32 * 1024 || body.trim().is_empty() {
        return Err(Error::bad("渲染后的正文为空或过长"));
    }
    let footer = format!(
        "\n事件 ID：{}",
        c.get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    );
    let (html, plain, markdown) = if source.format != "text" {
        fragment(&body, provider)?
    } else {
        (escape(&body), body.clone(), String::new())
    };
    if plain.trim().is_empty() {
        return Err(Error::bad("渲染后的正文不能为空"));
    }
    let text_body = format!("{subject}\n{plain}{footer}");
    let html_body = if provider == "feishu" && source.format == "html" {
        format!(
            "<b>{}</b>\n{html}<hr>{}",
            escape(&subject),
            escape(footer.trim_start())
        )
    } else if source.format != "text" {
        format!("<b>{}</b>\n{html}{}", escape(&subject), escape(&footer))
    } else {
        escape(&text_body)
    };
    let payload = if provider == "telegram" {
        if source.format != "rich_html" && text_body.encode_utf16().count() > 4096 {
            return Err(Error::bad("Telegram 消息不能超过 4096 UTF-16 单位"));
        }
        if source.format == "rich_html" {
            json!({"rich_message":{"html":html_body}})
        } else if source.format == "html" {
            json!({"text":html_body,"parse_mode":"HTML","link_preview_options":{"is_disabled":true}})
        } else {
            json!({"text":text_body,"link_preview_options":{"is_disabled":true}})
        }
    } else if source.format == "html" {
        let event = c
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let color = if event == "scanner.recovered" {
            "green"
        } else if c.get("severity").and_then(Value::as_str) == Some("critical") {
            "red"
        } else if matches!(event, "health.alert" | "scanner.offline") {
            "orange"
        } else {
            "blue"
        };
        json!({
            "msg_type":"interactive",
            "card":{
                "schema":"2.0",
                "header":{"template":color,"title":{"tag":"plain_text","content":subject}},
                "body":{"elements":[
                    {"tag":"markdown","content":markdown},
                    {"tag":"hr"},
                    {"tag":"markdown","content":card_text(footer.trim_start())}
                ]}
            }
        })
    } else {
        json!({"msg_type":"text","content":{"text":text_body}})
    };
    // Reserve room for Feishu signing fields. TG transport also bounds encoded payload size.
    if serde_json::to_vec(&payload)
        .map_err(|_| Error::bad("消息编码失败"))?
        .len()
        > 19 * 1024
    {
        return Err(Error::bad("消息编码后超过 19 KiB，请缩短内容"));
    }
    Ok(Rendered {
        subject,
        text_body,
        html_body,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_rich_html_uses_rich_message_payload() {
        let source = Source {
            format: "rich_html".into(),
            title_template: "标题".into(),
            body_template: "<b>内容</b>".into(),
        };
        let rendered = render("telegram", &source, &sample_context("user.login")).unwrap();
        assert!(
            rendered.payload["rich_message"]["html"]
                .as_str()
                .unwrap()
                .contains("<b>内容</b>")
        );
        assert!(rendered.payload.get("text").is_none());
        assert!(render("feishu", &source, &sample_context("user.login")).is_err());
    }
    #[test]
    fn event_defaults_and_parameter_catalog_match_mail_for_every_provider() {
        for event in crate::notification::EVENT_TYPES {
            let key = super::super::template_context::key(event).unwrap();
            let variables = super::super::template_context::variables(event);
            assert_eq!(
                serde_json::to_value(&variables).unwrap(),
                serde_json::to_value(crate::mail_template::template_variables(key)).unwrap()
            );
            let sample = sample_context(event);
            for variable in variables {
                assert!(
                    sample.get(variable.key).is_some(),
                    "{event}: {}",
                    variable.key
                );
            }
            for provider in ["feishu", "telegram"] {
                let rendered =
                    validate_source(provider, &event_default_source(event), event).unwrap();
                assert!(rendered.text_body.contains("Network Mapping"));
                if event == "user.login" {
                    assert!(rendered.text_body.contains("192.0.2.10"));
                }
                if event == "scanner.recovered" {
                    assert!(rendered.text_body.contains("恢复"));
                }
                if event.starts_with("report.") {
                    assert!(rendered.text_body.contains("核心指标"));
                }
            }
        }
    }

    #[test]
    fn same_render_drives_native_payload_and_safe_preview() {
        let source = Source {
            format: "html".into(),
            title_template: "{{ title }}".into(),
            body_template:
                "<b>{{ body }}</b>\n<a href=\"https://example.com?a=1&amp;b=2\"><i>查看</i></a>"
                    .into(),
        };
        let c = context(
            "user.login",
            "登录",
            "<script>&危险",
            "warning",
            "id",
            "now",
        );
        let feishu = render("feishu", &source, &c).unwrap();
        assert_eq!(feishu.payload["msg_type"], "interactive");
        assert_eq!(feishu.payload["card"]["schema"], "2.0");
        assert_eq!(
            feishu.payload["card"]["header"]["title"],
            json!({"tag":"plain_text","content":"登录"})
        );
        assert_eq!(
            feishu.payload["card"]["body"]["elements"][0],
            json!({
                "tag":"markdown",
            "content":"**&#60;script&#62;&#38;危险**<br>[*查看*](https://example.com?a=1&amp;b=2)"
            })
        );
        assert!(feishu.payload.get("content").is_none());
        assert_eq!(
            feishu.html_body,
            "<b>登录</b>\n<b>&lt;script&gt;&amp;危险</b>\n<a href=\"https://example.com?a=1&amp;b=2\"><i>查看</i></a><hr>事件 ID：id"
        );
        assert!(!feishu.html_body.contains("<script>"));
        let tg = render("telegram", &source, &c).unwrap();
        assert_eq!(tg.payload["parse_mode"], "HTML");
        assert!(tg.text_body.contains("事件 ID：id"));
        assert_eq!(tg.payload["text"], tg.html_body);
        assert!(tg.html_body.contains("<b>&lt;script&gt;&amp;危险</b>"));
        assert!(tg.html_body.contains("<i>查看</i>"));
    }

    #[test]
    fn card_styles_nesting_line_breaks_and_links_preserve_literal_data() {
        let source = Source {
            format: "html".into(),
            title_template: "{{ title }}".into(),
            body_template: "<strong>  标题 <em>斜体</em> </strong>\n\n<del>删除</del> <ins>下划线</ins>\n<b>一\n二</b>\n<a href=\"https://example.com/a_(b)?q=[x]&amp;v=2\">{{ body }}</a>".into(),
        };
        let c = context(
            "health.alert",
            "<标题> [test]",
            "**普通文本** <at id=all></at> [伪链接](https://evil.example) ![图片](x)",
            "critical",
            "id",
            "now",
        );
        let rendered = render("feishu", &source, &c).unwrap();
        let markdown = rendered.payload["card"]["body"]["elements"][0]["content"]
            .as_str()
            .unwrap();
        assert!(
            markdown
                .starts_with("  **标题 *斜体*** <br><br>~~删除~~ 下划线<br>**一**<br>**二**<br>")
        );
        assert!(markdown.contains("&#42;&#42;普通文本&#42;&#42;"));
        assert!(markdown.contains("&#60;at id&#61;all&#62;&#60;&#47;at&#62;"));
        assert!(!markdown.contains("<at"));
        assert!(!markdown.contains("!["));
        assert!(!markdown.contains("[伪链接]"));
        assert!(markdown.ends_with("](https://example.com/a_%28b%29?q=%5Bx%5D&amp;v=2)"));
        assert!(!rendered.html_body.contains("<u>"));
        assert!(rendered.html_body.contains("<s>删除</s>"));
        assert_eq!(
            rendered.payload["card"]["header"]["title"]["content"],
            "<标题> [test]"
        );
        assert_eq!(rendered.payload["card"]["body"]["elements"][1]["tag"], "hr");
        assert_eq!(
            rendered.payload["card"]["body"]["elements"][2]["content"],
            "事件 ID：id"
        );
    }

    #[test]
    fn card_header_colors_follow_event_and_severity_and_plain_text_stays_literal() {
        for (event, severity, color) in [
            ("health.alert", "warning", "orange"),
            ("health.alert", "critical", "red"),
            ("scanner.offline", "warning", "orange"),
            ("scanner.recovered", "critical", "green"),
            ("user.login", "warning", "blue"),
            ("report.weekly", "warning", "blue"),
        ] {
            let mut c = sample_context(event);
            c.insert("severity", severity);
            let rendered = render("feishu", &event_default_source(event), &c).unwrap();
            assert_eq!(rendered.payload["card"]["header"]["template"], color);
        }
        let source = Source {
            body_template: "<b>literal</b> **literal**".into(),
            ..default_source()
        };
        let rendered = render("feishu", &source, &sample_context("health.alert")).unwrap();
        assert_eq!(rendered.payload["msg_type"], "text");
        assert!(
            rendered.payload["content"]["text"]
                .as_str()
                .unwrap()
                .contains(&source.body_template)
        );
        let source = Source {
            format: "html".into(),
            body_template: "#".repeat(4000),
            ..default_source()
        };
        assert!(render("feishu", &source, &sample_context("health.alert")).is_err());
    }
    #[test]
    fn rejects_unsupported_styles_bad_nesting_and_unsafe_links() {
        for body in [
            "<script>x</script>",
            "<b style=\"color:red\">x</b>",
            "<b><i>x</b></i>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<b>x",
            "<b> </b>",
            "&bogus;",
            "<a href=\"https://a\" onclick=\"x\">x</a>",
            "<a href=\"https://a\"><a href=\"https://b\">x</a></a>",
        ] {
            let source = Source {
                format: "html".into(),
                body_template: body.into(),
                ..default_source()
            };
            for provider in ["feishu", "telegram"] {
                assert!(
                    render(provider, &source, &sample_context("health.alert")).is_err(),
                    "{provider}: {body}"
                );
            }
        }
    }
    #[test]
    fn plain_mode_is_literal_and_length_limits_use_decoded_text() {
        let mut s = default_source();
        s.body_template = "<b>literal</b>".into();
        let r = render("telegram", &s, &sample_context("health.alert")).unwrap();
        assert!(r.payload.get("parse_mode").is_none());
        assert!(r.html_body.contains("&lt;b&gt;"));
        assert!(!r.html_body.contains("<b>"));
        s.format = "html".into();
        s.body_template = "😀".repeat(2100);
        assert!(render("telegram", &s, &sample_context("health.alert")).is_err());
        s.body_template = "{{ unknown }}".into();
        assert!(render("feishu", &s, &sample_context("health.alert")).is_err());
    }
}
