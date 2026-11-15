//! 本地搜索 DSL AST → 平台查询语法（第二个编译目标，§5）。
//!
//! 保守原则：平台不支持的构造 → 该源跳过（Err），绝不丢谓词放大查询。
//! 平台语义宽于本地时（如 Shodan hostname 包含匹配），产出残余谓词在归一化后精过滤（§5.5）。

use crate::handlers::search_dsl::{Expr, Field, Operator, Predicate};

use super::model::{FieldSelection, SourceKind};

/// 翻译产物：平台查询串 + 本地残余谓词 + 标注。
#[derive(Clone, Debug)]
pub(crate) struct PlatformQuery {
    pub text: String,
    pub(crate) residual: Option<Expr>,
    /// tech 查询的版本部分被丢弃（平台指纹不带精确版本）。
    pub version_ignored: bool,
}

#[derive(Default)]
struct Ctx {
    version_ignored: bool,
    residual: Option<Expr>,
}

impl Ctx {
    fn add_residual(&mut self, expr: Expr) {
        self.residual = Some(match self.residual.take() {
            Some(existing) => Expr::And(Box::new(existing), Box::new(expr)),
            None => expr,
        });
    }
}

pub(crate) fn translate(
    kind: SourceKind,
    expr: &Expr,
    _fields: &FieldSelection,
) -> Result<PlatformQuery, String> {
    let mut ctx = Ctx::default();
    let text = match kind {
        SourceKind::Hunter => hunter(expr, &mut ctx)?,
        SourceKind::Quake => quake(expr, &mut ctx)?,
        SourceKind::Fofa => fofa(expr, &mut ctx)?,
        SourceKind::Shodan => shodan(expr, &mut ctx)?,
    };
    if text.trim().is_empty() {
        return Err("unsupported: empty query".into());
    }
    if kind == SourceKind::Hunter && text.chars().count() > 2048 {
        return Err("unsupported: hunter query exceeds 2048 chars".into());
    }
    Ok(PlatformQuery {
        text,
        residual: ctx.residual,
        version_ignored: ctx.version_ignored,
    })
}

/// 收集 AST 涉及的联测字段名（trigger_fields 判定用，§5.4）。
pub(crate) fn collect_fields(expr: &Expr) -> Vec<&'static str> {
    let mut fields = Vec::new();
    visit_fields(expr, &mut fields);
    fields.sort_unstable();
    fields.dedup();
    fields
}

fn visit_fields(expr: &Expr, out: &mut Vec<&'static str>) {
    match expr {
        Expr::Predicate(p) => {
            if let Some(name) = federation_field(p.field) {
                out.push(name);
            }
        }
        Expr::And(l, r) | Expr::Or(l, r) => {
            visit_fields(l, out);
            visit_fields(r, out);
        }
        Expr::Not(inner) | Expr::HasEndpoint(inner) => visit_fields(inner, out),
    }
}

pub(crate) fn federation_field(field: Field) -> Option<&'static str> {
    match field {
        Field::Ip => Some("ip"),
        Field::Domain => Some("domain"),
        Field::Port => Some("port"),
        Field::Service => Some("service"),
        Field::Technology => Some("tech"),
        Field::Title => Some("title"),
        Field::Banner => Some("banner"),
        _ => None,
    }
}

// ---- 共享辅助 ----

fn escape_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", escape_quoted(value))
}

fn first_value(p: &Predicate) -> Result<&str, String> {
    p.values
        .first()
        .map(String::as_str)
        .ok_or_else(|| "unsupported: empty predicate values".into())
}

/// tech 值拆分 id@version。
fn tech_split(value: &str) -> (&str, Option<&str>) {
    match value.split_once('@') {
        Some((name, version)) if !version.is_empty() => (name, Some(version)),
        _ => (value, None),
    }
}

fn negate(p: &Predicate) -> Option<Predicate> {
    let operator = match p.operator {
        Operator::Eq => Operator::NotEq,
        Operator::NotEq => Operator::Eq,
        Operator::Contains => Operator::NotContains,
        Operator::NotContains => Operator::Contains,
        Operator::In => Operator::NotIn,
        Operator::NotIn => Operator::In,
        _ => return None,
    };
    Some(Predicate {
        field: p.field,
        operator,
        values: p.values.clone(),
    })
}

/// Shodan product 别名表（service → product）；未映射 → unsupported。
fn shodan_product(service: &str) -> Option<&'static str> {
    match service.to_ascii_lowercase().as_str() {
        "mysql" | "mariadb" => Some("MySQL"),
        "postgresql" => Some("PostgreSQL"),
        "mongodb" => Some("MongoDB"),
        "redis" => Some("Redis"),
        "elasticsearch" => Some("Elasticsearch"),
        "ssh" => Some("OpenSSH"),
        "ftp" => Some("FTP"),
        "smtp" => Some("SMTP"),
        "pop3" => Some("POP3"),
        "imap" => Some("IMAP"),
        "telnet" => Some("Telnet"),
        "vnc" => Some("VNC"),
        "mqtt" => Some("MQTT"),
        "modbus" => Some("Modbus"),
        "nginx" => Some("nginx"),
        "apache" => Some("Apache"),
        _ => None,
    }
}

// ---- Hunter（= 模糊 / == 精确 / != 模糊剔除 / && / ||）----

fn hunter(expr: &Expr, ctx: &mut Ctx) -> Result<String, String> {
    match expr {
        Expr::And(l, r) => Ok(format!("({} && {})", hunter(l, ctx)?, hunter(r, ctx)?)),
        Expr::Or(l, r) => Ok(format!("({} || {})", hunter(l, ctx)?, hunter(r, ctx)?)),
        Expr::Not(inner) => match inner.as_ref() {
            Expr::Predicate(p) => {
                let negated = negate(p).ok_or("unsupported: hunter NOT operator")?;
                hunter_predicate(&negated, ctx)
            }
            _ => Err("unsupported: hunter NOT of complex expression".into()),
        },
        Expr::Predicate(p) => hunter_predicate(p, ctx),
        Expr::HasEndpoint(_) => Err("unsupported: has_endpoint".into()),
    }
}

fn hunter_predicate(p: &Predicate, ctx: &mut Ctx) -> Result<String, String> {
    let join = |op: &str, values: &[String]| -> String {
        values
            .iter()
            .map(|v| format!("{op}{}", quoted(v)))
            .collect::<Vec<_>>()
            .join(" || ")
    };
    match (p.field, p.operator) {
        (Field::Ip, Operator::Eq) => Ok(format!("ip={}", quoted(first_value(p)?))),
        (Field::Ip, Operator::In) => Ok(format!("({})", join("ip=", &p.values))),
        (Field::Ip, Operator::NotEq) => Ok(format!("ip!={}", quoted(first_value(p)?))),
        (Field::Ip, Operator::NotIn) => Ok(p
            .values
            .iter()
            .map(|v| format!("ip!={}", quoted(v)))
            .collect::<Vec<_>>()
            .join(" && ")),
        (Field::Domain, Operator::Eq) => Ok(format!("domain=={}", quoted(first_value(p)?))),
        (Field::Domain, Operator::Contains) => Ok(format!("domain={}", quoted(first_value(p)?))),
        (Field::Domain, Operator::In) => Ok(format!("({})", join("domain==", &p.values))),
        (Field::Domain, Operator::NotEq) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("domain!={}", quoted(first_value(p)?)))
        }
        (Field::Port, Operator::Eq) => Ok(format!("ip.port={}", quoted(first_value(p)?))),
        (Field::Port, Operator::In) => Ok(format!("({})", join("ip.port=", &p.values))),
        (Field::Service, Operator::Eq) => Ok(format!("protocol={}", quoted(first_value(p)?))),
        (Field::Service, Operator::NotEq) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("protocol!={}", quoted(first_value(p)?)))
        }
        (Field::Technology, Operator::Eq) => {
            let (name, version) = tech_split(first_value(p)?);
            if version.is_some() {
                ctx.version_ignored = true;
            }
            Ok(format!("app.name={}", quoted(name)))
        }
        (Field::Title, Operator::Eq) => Ok(format!("web.title=={}", quoted(first_value(p)?))),
        (Field::Title, Operator::Contains) => Ok(format!("web.title={}", quoted(first_value(p)?))),
        (Field::Title, Operator::NotEq) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("web.title!={}", quoted(first_value(p)?)))
        }
        (Field::Banner, Operator::Contains) => {
            Ok(format!("protocol.banner={}", quoted(first_value(p)?)))
        }
        (Field::Title, Operator::Exists) => Ok("web.title!=\"\"".into()),
        (Field::Domain, Operator::Exists) => Ok("domain!=\"\"".into()),
        _ => Err(format!(
            "unsupported: hunter {:?} {:?}",
            p.field, p.operator
        )),
    }
}

// ---- Quake（field:"value" / AND / OR / NOT / _exists_）----

fn quake(expr: &Expr, ctx: &mut Ctx) -> Result<String, String> {
    match expr {
        Expr::And(l, r) => Ok(format!("({} AND {})", quake(l, ctx)?, quake(r, ctx)?)),
        Expr::Or(l, r) => Ok(format!("({} OR {})", quake(l, ctx)?, quake(r, ctx)?)),
        Expr::Not(inner) => Ok(format!("(NOT {})", quake(inner, ctx)?)),
        Expr::Predicate(p) => quake_predicate(p, ctx),
        Expr::HasEndpoint(_) => Err("unsupported: has_endpoint".into()),
    }
}

fn quake_predicate(p: &Predicate, ctx: &mut Ctx) -> Result<String, String> {
    let join = |field: &str, values: &[String]| -> String {
        values
            .iter()
            .map(|v| format!("{field}:{}", quoted(v)))
            .collect::<Vec<_>>()
            .join(" OR ")
    };
    match (p.field, p.operator) {
        (Field::Ip, Operator::Eq) => Ok(format!("ip:{}", quoted(first_value(p)?))),
        (Field::Ip, Operator::In) => Ok(format!("({})", join("ip", &p.values))),
        (Field::Ip, Operator::NotEq) => Ok(format!("NOT ip:{}", quoted(first_value(p)?))),
        (Field::Domain, Operator::Eq) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("domain:{}", quoted(first_value(p)?)))
        }
        (Field::Domain, Operator::Contains) => Ok(format!("domain:{}", quoted(first_value(p)?))),
        (Field::Domain, Operator::In) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("({})", join("domain", &p.values)))
        }
        (Field::Port, Operator::Eq) => Ok(format!("port:{}", quoted(first_value(p)?))),
        (Field::Port, Operator::In) => Ok(format!("({})", join("port", &p.values))),
        (Field::Service, Operator::Eq) => Ok(format!("service:{}", quoted(first_value(p)?))),
        (Field::Technology, Operator::Eq) => {
            let (name, version) = tech_split(first_value(p)?);
            if version.is_some() {
                ctx.version_ignored = true;
            }
            Ok(format!("app:{}", quoted(name)))
        }
        (Field::Title, Operator::Eq | Operator::Contains) => {
            Ok(format!("title:{}", quoted(first_value(p)?)))
        }
        (Field::Banner, Operator::Contains) => Ok(format!("response:{}", quoted(first_value(p)?))),
        (Field::Domain, Operator::Exists) => Ok("_exists_:domain".into()),
        (Field::Service, Operator::Exists) => Ok("_exists_:service.name".into()),
        _ => Err(format!("unsupported: quake {:?} {:?}", p.field, p.operator)),
    }
}

// ---- FOFA（= 包含 / == 精确 / != / *= / && / ||）----

fn fofa(expr: &Expr, ctx: &mut Ctx) -> Result<String, String> {
    match expr {
        Expr::And(l, r) => Ok(format!("({} && {})", fofa(l, ctx)?, fofa(r, ctx)?)),
        Expr::Or(l, r) => Ok(format!("({} || {})", fofa(l, ctx)?, fofa(r, ctx)?)),
        Expr::Not(inner) => match inner.as_ref() {
            Expr::Predicate(p) => {
                let negated = negate(p).ok_or("unsupported: fofa NOT operator")?;
                fofa_predicate(&negated, ctx)
            }
            _ => Err("unsupported: fofa NOT of complex expression".into()),
        },
        Expr::Predicate(p) => fofa_predicate(p, ctx),
        Expr::HasEndpoint(_) => Err("unsupported: has_endpoint".into()),
    }
}

fn fofa_predicate(p: &Predicate, ctx: &mut Ctx) -> Result<String, String> {
    let join = |op: &str, values: &[String]| -> String {
        values
            .iter()
            .map(|v| format!("{op}{}", quoted(v)))
            .collect::<Vec<_>>()
            .join(" || ")
    };
    match (p.field, p.operator) {
        (Field::Ip, Operator::Eq) => Ok(format!("ip={}", quoted(first_value(p)?))),
        (Field::Ip, Operator::In) => Ok(format!("({})", join("ip=", &p.values))),
        (Field::Ip, Operator::NotEq) => Ok(format!("ip!={}", quoted(first_value(p)?))),
        (Field::Ip, Operator::NotIn) => Ok(p
            .values
            .iter()
            .map(|v| format!("ip!={}", quoted(v)))
            .collect::<Vec<_>>()
            .join(" && ")),
        (Field::Domain, Operator::Eq) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("domain={}", quoted(first_value(p)?)))
        }
        (Field::Domain, Operator::Contains) => Ok(format!("domain={}", quoted(first_value(p)?))),
        (Field::Domain, Operator::In) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("({})", join("domain=", &p.values)))
        }
        (Field::Port, Operator::Eq) => Ok(format!("port={}", quoted(first_value(p)?))),
        (Field::Port, Operator::In) => Ok(format!("({})", join("port=", &p.values))),
        (Field::Service, Operator::Eq) => Ok(format!("protocol={}", quoted(first_value(p)?))),
        (Field::Technology, Operator::Eq) => {
            let (name, version) = tech_split(first_value(p)?);
            if version.is_some() {
                ctx.version_ignored = true;
            }
            Ok(format!("app={}", quoted(name)))
        }
        (Field::Title, Operator::Eq) => Ok(format!("title=={}", quoted(first_value(p)?))),
        (Field::Title, Operator::Contains) => Ok(format!("title={}", quoted(first_value(p)?))),
        (Field::Banner, Operator::Contains) => Ok(format!("banner={}", quoted(first_value(p)?))),
        (Field::Title, Operator::Exists) => Ok("title!=\"\"".into()),
        (Field::Domain, Operator::Exists) => Ok("domain!=\"\"".into()),
        (Field::Service, Operator::Exists) => Ok("protocol!=\"\"".into()),
        _ => Err(format!("unsupported: fofa {:?} {:?}", p.field, p.operator)),
    }
}

// ---- Shodan（filter:value / 空格 AND / 同字段逗号 OR / - 前缀 NOT）----

fn shodan(expr: &Expr, ctx: &mut Ctx) -> Result<String, String> {
    match expr {
        Expr::And(l, r) => Ok(format!("{} {}", shodan(l, ctx)?, shodan(r, ctx)?)),
        Expr::Or(l, r) => shodan_or(l, r, ctx),
        Expr::Not(inner) => match inner.as_ref() {
            Expr::Predicate(p) => {
                let positive = shodan_predicate(p, ctx)?;
                Ok(format!("-{positive}"))
            }
            _ => Err("unsupported: shodan NOT of complex expression".into()),
        },
        Expr::Predicate(p) => shodan_predicate(p, ctx),
        Expr::HasEndpoint(_) => Err("unsupported: has_endpoint".into()),
    }
}

/// 同字段 OR → 逗号值；跨字段 OR → unsupported。
fn shodan_or(l: &Expr, r: &Expr, ctx: &mut Ctx) -> Result<String, String> {
    if let (Expr::Predicate(a), Expr::Predicate(b)) = (l, r)
        && a.field == b.field
        && matches!(a.operator, Operator::Eq | Operator::In)
        && matches!(b.operator, Operator::Eq | Operator::In)
    {
        let mut merged = a.values.clone();
        merged.extend(b.values.iter().cloned());
        let predicate = Predicate {
            field: a.field,
            operator: Operator::In,
            values: merged,
        };
        return shodan_predicate(&predicate, ctx);
    }
    Err("unsupported: shodan cross-field OR".into())
}

fn shodan_value(value: &str) -> String {
    if value.contains(' ') {
        quoted(value)
    } else {
        escape_quoted(value)
    }
}

fn shodan_predicate(p: &Predicate, ctx: &mut Ctx) -> Result<String, String> {
    match (p.field, p.operator) {
        (Field::Ip, Operator::Eq | Operator::In) => {
            let cidr = p.values.iter().any(|v| v.contains('/'));
            let filter = if cidr { "net" } else { "ip" };
            Ok(format!(
                "{filter}:{}",
                p.values
                    .iter()
                    .map(|v| shodan_value(v))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
        }
        (Field::Domain, Operator::Eq | Operator::In) => {
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!(
                "hostname:{}",
                p.values
                    .iter()
                    .map(|v| shodan_value(v))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
        }
        (Field::Port, Operator::Eq | Operator::In) => Ok(format!(
            "port:{}",
            p.values
                .iter()
                .map(|v| shodan_value(v))
                .collect::<Vec<_>>()
                .join(",")
        )),
        (Field::Service, Operator::Eq) => {
            let product = shodan_product(first_value(p)?)
                .ok_or_else(|| "unsupported: shodan service without product mapping".to_owned())?;
            ctx.add_residual(Expr::Predicate(p.clone()));
            Ok(format!("product:{}", shodan_value(product)))
        }
        (Field::Technology, Operator::Eq) => {
            let (name, version) = tech_split(first_value(p)?);
            if version.is_some() {
                ctx.version_ignored = true;
            }
            Ok(format!("http.component:{}", shodan_value(name)))
        }
        (Field::Title, Operator::Eq | Operator::Contains) => {
            Ok(format!("http.title:{}", quoted(first_value(p)?)))
        }
        (Field::Banner, Operator::Contains) => Ok(shodan_value(first_value(p)?)),
        _ => Err(format!(
            "unsupported: shodan {:?} {:?}",
            p.field, p.operator
        )),
    }
}

// ---- 残余谓词求值（§5.5，归一化后逐条执行）----

pub(crate) fn eval_residual(expr: &Expr, record: &super::model::NormalizedRecord) -> bool {
    match expr {
        Expr::And(l, r) => eval_residual(l, record) && eval_residual(r, record),
        Expr::Or(l, r) => eval_residual(l, record) || eval_residual(r, record),
        Expr::Not(inner) => !eval_residual(inner, record),
        Expr::HasEndpoint(_) => false,
        Expr::Predicate(p) => eval_predicate(p, record),
    }
}

fn record_values(field: Field, record: &super::model::NormalizedRecord) -> Vec<String> {
    match field {
        Field::Ip => vec![record.ip.clone()],
        Field::Domain => record.domain.clone().into_iter().collect(),
        Field::Port => vec![record.port.to_string()],
        Field::Service => record.service.clone().into_iter().collect(),
        Field::Technology => record
            .tech
            .iter()
            .map(|t| match &t.version {
                Some(v) => format!("{}@{}", t.id, v),
                None => t.id.clone(),
            })
            .collect(),
        Field::Title => record.title.clone().into_iter().collect(),
        Field::Banner => record.banner.clone().into_iter().collect(),
        _ => Vec::new(),
    }
}

fn eval_predicate(p: &Predicate, record: &super::model::NormalizedRecord) -> bool {
    let values = record_values(p.field, record);
    let eq = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    match p.operator {
        Operator::Eq => p
            .values
            .first()
            .is_some_and(|target| values.iter().any(|v| eq(v, target))),
        Operator::In => values
            .iter()
            .any(|v| p.values.iter().any(|target| eq(v, target))),
        Operator::Contains => p.values.first().is_some_and(|target| {
            let target = target.to_ascii_lowercase();
            values
                .iter()
                .any(|v| v.to_ascii_lowercase().contains(&target))
        }),
        Operator::NotEq => p
            .values
            .first()
            .is_none_or(|target| !values.iter().any(|v| eq(v, target))),
        Operator::NotIn => !values
            .iter()
            .any(|v| p.values.iter().any(|target| eq(v, target))),
        Operator::NotContains => p.values.first().is_none_or(|target| {
            let target = target.to_ascii_lowercase();
            !values
                .iter()
                .any(|v| v.to_ascii_lowercase().contains(&target))
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::model::NormalizedRecord;
    use crate::handlers::search_dsl::parse_query_ast;

    fn translate_ok(kind: SourceKind, query: &str) -> PlatformQuery {
        let expr = parse_query_ast(query).expect("parse");
        translate(kind, &expr, &FieldSelection::default()).expect("translate")
    }

    fn record() -> NormalizedRecord {
        NormalizedRecord {
            ip: "1.1.1.1".into(),
            port: 443,
            protocol: "tcp".into(),
            domain: Some("www.example.com".into()),
            service: Some("https".into()),
            tech: vec![],
            title: Some("Example".into()),
            banner: None,
            observed_at: 0,
            timestamp_inferred: false,
            asn: None,
            as_org: None,
            isp: None,
            country_name: None,
            region_name: None,
            city_name: None,
            latitude: None,
            longitude: None,
            sources: vec!["fofa".into()],
        }
    }

    #[test]
    fn hunter_basic_syntax() {
        assert_eq!(
            translate_ok(SourceKind::Hunter, "ip = \"1.1.1.1\"").text,
            "ip=\"1.1.1.1\""
        );
        assert_eq!(
            translate_ok(SourceKind::Hunter, "port = 443").text,
            "ip.port=\"443\""
        );
        assert_eq!(
            translate_ok(SourceKind::Hunter, "domain = \"example.com\"").text,
            "domain==\"example.com\""
        );
        assert_eq!(
            translate_ok(SourceKind::Hunter, "tech = \"jquery@3.7.1\"").text,
            "app.name=\"jquery\""
        );
        assert!(translate_ok(SourceKind::Hunter, "tech = \"jquery@3.7.1\"").version_ignored);
        assert_eq!(
            translate_ok(SourceKind::Hunter, "ip = \"1.1.1.1\" AND port = 443").text,
            "(ip=\"1.1.1.1\" && ip.port=\"443\")"
        );
    }

    #[test]
    fn quake_boolean_and_residual() {
        let q = translate_ok(SourceKind::Quake, "domain = \"example.com\" AND port = 443");
        assert_eq!(q.text, "(domain:\"example.com\" AND port:\"443\")");
        assert!(q.residual.is_some());
        let expr = parse_query_ast("domain = \"www.example.com\"").unwrap();
        let residual = translate(SourceKind::Quake, &expr, &FieldSelection::default())
            .unwrap()
            .residual
            .unwrap();
        assert!(eval_residual(&residual, &record()));
        let mut other = record();
        other.domain = Some("api.example.com".into());
        assert!(!eval_residual(&residual, &other));
    }

    #[test]
    fn fofa_syntax_and_not() {
        assert_eq!(
            translate_ok(SourceKind::Fofa, "ip = \"1.1.1.1\"").text,
            "ip=\"1.1.1.1\""
        );
        assert_eq!(
            translate_ok(SourceKind::Fofa, "title = \"bing\"").text,
            "title==\"bing\""
        );
        assert_eq!(
            translate_ok(SourceKind::Fofa, "NOT ip = \"1.1.1.1\"").text,
            "ip!=\"1.1.1.1\""
        );
        assert_eq!(
            translate_ok(SourceKind::Fofa, "ip IN (\"1.1.1.1\", \"2.2.2.2\")").text,
            "(ip=\"1.1.1.1\" || ip=\"2.2.2.2\")"
        );
    }

    #[test]
    fn shodan_or_rules_and_free_ip() {
        assert_eq!(
            translate_ok(SourceKind::Shodan, "port = 443").text,
            "port:443"
        );
        assert_eq!(
            translate_ok(SourceKind::Shodan, "ip = \"1.1.1.0/24\"").text,
            "net:1.1.1.0/24"
        );
        assert_eq!(
            translate_ok(SourceKind::Shodan, "port IN (80, 443)").text,
            "port:80,443"
        );
        // 同字段 OR 允许
        assert_eq!(
            translate_ok(SourceKind::Shodan, "port = 80 OR port = 443").text,
            "port:80,443"
        );
        // 跨字段 OR 拒绝
        let expr = parse_query_ast("port = 80 OR ip = \"1.1.1.1\"").unwrap();
        assert!(translate(SourceKind::Shodan, &expr, &FieldSelection::default()).is_err());
        // NOT 前缀
        assert_eq!(
            translate_ok(SourceKind::Shodan, "NOT port = 22").text,
            "-port:22"
        );
    }

    #[test]
    fn unsupported_constructs_skip_source() {
        for kind in SourceKind::ALL {
            let expr = parse_query_ast("has_endpoint(port = 80)").unwrap();
            assert!(translate(kind, &expr, &FieldSelection::default()).is_err());
            let expr = parse_query_ast("tls.self_signed = true").unwrap();
            assert!(translate(kind, &expr, &FieldSelection::default()).is_err());
        }
        // Shodan 无 http/https 的 product 映射
        let expr = parse_query_ast("service = \"http\"").unwrap();
        assert!(translate(SourceKind::Shodan, &expr, &FieldSelection::default()).is_err());
        // Hunter EXISTS 仅 title/domain
        let expr = parse_query_ast("EXISTS(banner)").unwrap();
        assert!(translate(SourceKind::Hunter, &expr, &FieldSelection::default()).is_err());
        let expr = parse_query_ast("EXISTS(title)").unwrap();
        assert!(translate(SourceKind::Hunter, &expr, &FieldSelection::default()).is_ok());
    }

    #[test]
    fn collect_fields_for_trigger() {
        let expr =
            parse_query_ast("ip = \"1.1.1.1\" AND tech = \"nginx\" AND tag = \"prod\"").unwrap();
        assert_eq!(collect_fields(&expr), vec!["ip", "tech"]);
    }

    #[test]
    fn escaping_quotes() {
        let q = translate_ok(SourceKind::Fofa, "title = \"a\\\"b\"");
        assert!(q.text.contains("a\\\"b"));
    }
}
