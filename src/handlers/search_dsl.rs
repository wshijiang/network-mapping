use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde_json::{Value, json};

const MAX_QUERY_LENGTH: usize = 2_048;
const MAX_DEPTH: usize = 12;
const MAX_PREDICATES: usize = 50;
const MAX_IN_VALUES: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Expr {
    Predicate(Predicate),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    HasEndpoint(Box<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Predicate {
    field: Field,
    operator: Operator,
    values: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Field {
    Ip,
    Domain,
    Asn,
    Isp,
    Org,
    Country,
    City,
    Tag,
    TagId,
    TagKind,
    TagCategory,
    Port,
    Protocol,
    Service,
    Banner,
    OsFamily,
    OsDistribution,
    OsVersion,
    OsConfidence,
    OsStatus,
    OsScore,
    Title,
    HttpBody,
    TlsMode,
    TlsVersion,
    TlsCipherSuite,
    TlsSubject,
    TlsIssuer,
    TlsNames,
    TlsSerialNumber,
    TlsNotBefore,
    TlsNotAfter,
    TlsFingerprintSha256,
    TlsSelfSigned,
    Source,
    Scanner,
    FirstSeen,
    LastSeen,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Operator {
    Eq,
    NotEq,
    Contains,
    NotContains,
    Greater,
    GreaterEq,
    Less,
    LessEq,
    In,
    NotIn,
    Colon,
    Exists,
}

#[derive(Clone, Debug, PartialEq)]
enum TokenKind {
    Word(String),
    String(String),
    LeftParen,
    RightParen,
    Comma,
    Eq,
    NotEq,
    Contains,
    NotContains,
    Greater,
    GreaterEq,
    Less,
    LessEq,
}

#[derive(Clone, Debug, PartialEq)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchSyntaxError {
    pub(crate) message: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl SearchSyntaxError {
    fn new(message: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            message: message.into(),
            start,
            end,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ElasticsearchCompilation {
    Supported(Value),
    RequiresElasticsearch(Value),
    Unsupported,
}

pub(crate) fn parse_and_compile_elasticsearch(
    query: &str,
) -> Result<ElasticsearchCompilation, SearchSyntaxError> {
    let (expression, normalized_query) = parse_expression(query)?;
    let mut compiler = ElasticsearchCompiler::default();
    let Some(filter) = compiler.compile_expr(&expression, false)? else {
        return Ok(ElasticsearchCompilation::Unsupported);
    };
    if compiler.predicate_count > MAX_PREDICATES {
        return Err(SearchSyntaxError::new(
            format!("查询条件不能超过 {MAX_PREDICATES} 个"),
            0,
            normalized_query.len(),
        ));
    }
    if compiler.requires_elasticsearch {
        Ok(ElasticsearchCompilation::RequiresElasticsearch(filter))
    } else {
        Ok(ElasticsearchCompilation::Supported(filter))
    }
}

/// A single explicit target, independent of endpoint filters. Ambiguous boolean
/// expressions deliberately do not authorize any task generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SearchTarget {
    pub kind: &'static str,
    pub key: String,
}

pub(crate) fn extract_search_target(query: &str) -> Option<SearchTarget> {
    fn visit(expr: &Expr, target: &mut Option<SearchTarget>) -> Option<()> {
        match expr {
            Expr::And(left, right) => {
                visit(left, target)?;
                visit(right, target)
            }
            Expr::Predicate(p) if matches!(p.field, Field::Ip | Field::Domain) => {
                if target.is_some()
                    || p.values.len() != 1
                    || !matches!(p.operator, Operator::Eq | Operator::Colon)
                {
                    return None;
                }
                *target = Some(match p.field {
                    Field::Ip => SearchTarget {
                        kind: "ip",
                        key: p.values[0].parse::<IpAddr>().ok()?.to_string(),
                    },
                    Field::Domain => SearchTarget {
                        kind: "domain",
                        key: crate::dns::canonical_scan_domain(&p.values[0]).ok()?,
                    },
                    _ => return None,
                });
                Some(())
            }
            Expr::Predicate(_) => Some(()),
            _ => None,
        }
    }
    let (expr, _) = parse_expression(query).ok()?;
    let mut target = None;
    visit(&expr, &mut target)?;
    target
}

#[derive(Default)]
struct ElasticsearchCompiler {
    predicate_count: usize,
    requires_elasticsearch: bool,
}

impl ElasticsearchCompiler {
    fn compile_expr(
        &mut self,
        expression: &Expr,
        endpoint_scope: bool,
    ) -> Result<Option<Value>, SearchSyntaxError> {
        match expression {
            Expr::Predicate(predicate) => {
                if endpoint_scope && !predicate.field.is_endpoint() {
                    return Err(SearchSyntaxError::new(
                        format!(
                            "has_endpoint 中不能使用资产字段 {}",
                            predicate.field.display_name()
                        ),
                        0,
                        0,
                    ));
                }
                self.predicate_count += 1;
                self.compile_predicate(predicate).map(Some)
            }
            Expr::And(left, right) => {
                let (Some(left), Some(right)) = (
                    self.compile_expr(left, endpoint_scope)?,
                    self.compile_expr(right, endpoint_scope)?,
                ) else {
                    return Ok(None);
                };
                Ok(Some(json!({"bool": {"filter": [left, right]}})))
            }
            Expr::Or(left, right) => {
                let (Some(left), Some(right)) = (
                    self.compile_expr(left, endpoint_scope)?,
                    self.compile_expr(right, endpoint_scope)?,
                ) else {
                    return Ok(None);
                };
                Ok(Some(json!({
                    "bool": {"should": [left, right], "minimum_should_match": 1}
                })))
            }
            Expr::Not(inner) => self.compile_negated_expr(inner, endpoint_scope),
            Expr::HasEndpoint(inner) => {
                if endpoint_scope {
                    return Err(SearchSyntaxError::new("has_endpoint 不能嵌套", 0, 0));
                }
                let Some(compiled) = self.compile_expr(inner, true)? else {
                    return Ok(None);
                };
                Ok(Some(json!({"network_mapping_has_endpoint": compiled})))
            }
        }
    }

    fn compile_negated_expr(
        &mut self,
        expression: &Expr,
        endpoint_scope: bool,
    ) -> Result<Option<Value>, SearchSyntaxError> {
        match expression {
            Expr::Predicate(predicate) => {
                if endpoint_scope && !predicate.field.is_endpoint() {
                    return Err(SearchSyntaxError::new(
                        format!(
                            "has_endpoint 中不能使用资产字段 {}",
                            predicate.field.display_name()
                        ),
                        0,
                        0,
                    ));
                }
                self.predicate_count += 1;
                let compiled = self.compile_predicate(predicate)?;
                if predicate.field == Field::Domain || predicate.operator == Operator::Exists {
                    Ok(Some(json!({"bool": {"must_not": [compiled]}})))
                } else {
                    Ok(Some(json!({"bool": {
                        "filter": [{"exists": {"field": es_field(predicate.field)}}],
                        "must_not": [compiled]
                    }})))
                }
            }
            Expr::And(left, right) => {
                let (Some(left), Some(right)) = (
                    self.compile_negated_expr(left, endpoint_scope)?,
                    self.compile_negated_expr(right, endpoint_scope)?,
                ) else {
                    return Ok(None);
                };
                Ok(Some(json!({
                    "bool": {"should": [left, right], "minimum_should_match": 1}
                })))
            }
            Expr::Or(left, right) => {
                let (Some(left), Some(right)) = (
                    self.compile_negated_expr(left, endpoint_scope)?,
                    self.compile_negated_expr(right, endpoint_scope)?,
                ) else {
                    return Ok(None);
                };
                Ok(Some(json!({"bool": {"filter": [left, right]}})))
            }
            Expr::Not(inner) => self.compile_expr(inner, endpoint_scope),
            Expr::HasEndpoint(inner) => {
                if endpoint_scope {
                    return Err(SearchSyntaxError::new("has_endpoint 不能嵌套", 0, 0));
                }
                let Some(compiled) = self.compile_expr(inner, true)? else {
                    return Ok(None);
                };
                Ok(Some(json!({"bool": {
                    "must_not": [{"network_mapping_has_endpoint": compiled}]
                }})))
            }
        }
    }

    fn compile_predicate(&mut self, predicate: &Predicate) -> Result<Value, SearchSyntaxError> {
        let operator = if predicate.operator == Operator::Colon {
            predicate.field.default_colon_operator()
        } else {
            predicate.operator
        };
        if predicate.field == Field::Domain && operator == Operator::Exists {
            return Err(SearchSyntaxError::new("字段 domain 不支持 EXISTS", 0, 0));
        }
        if operator == Operator::Exists {
            return Ok(json!({"exists": {"field": es_field(predicate.field)}}));
        }
        if predicate.values.is_empty() {
            return Err(SearchSyntaxError::new("搜索值不能为空", 0, 0));
        }
        match predicate.field {
            Field::Ip => self.compile_ip(operator, &predicate.values),
            Field::Domain => self.compile_domain(operator, &predicate.values),
            Field::Port | Field::TagId | Field::OsScore => {
                self.compile_integer(predicate.field, operator, &predicate.values)
            }
            Field::FirstSeen | Field::LastSeen | Field::TlsNotBefore | Field::TlsNotAfter => {
                self.compile_time(predicate.field, operator, &predicate.values)
            }
            Field::TlsSelfSigned => {
                self.compile_boolean(predicate.field, operator, &predicate.values)
            }
            field => self.compile_text(field, operator, &predicate.values),
        }
    }

    fn compile_domain(
        &mut self,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if !matches!(
            operator,
            Operator::Eq
                | Operator::NotEq
                | Operator::Contains
                | Operator::NotContains
                | Operator::In
                | Operator::NotIn
        ) {
            return Err(unsupported_operator(Field::Domain));
        }
        let values = values
            .iter()
            .map(|value| normalize_domain(value))
            .collect::<Result<Vec<_>, _>>()?;
        self.requires_elasticsearch = true;
        let operator = match operator {
            Operator::Eq => "eq",
            Operator::NotEq => "not_eq",
            Operator::Contains => "contains",
            Operator::NotContains => "not_contains",
            Operator::In => "in",
            Operator::NotIn => "not_in",
            _ => unreachable!(),
        };
        Ok(json!({"network_mapping_domain": {"operator": operator, "values": values}}))
    }

    fn compile_ip(
        &self,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if !matches!(
            operator,
            Operator::Eq | Operator::NotEq | Operator::In | Operator::NotIn
        ) {
            return Err(unsupported_operator(Field::Ip));
        }
        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            if value.contains('/') {
                normalized.push(normalize_network(value)?);
            } else {
                normalized.push(
                    IpAddr::from_str(value)
                        .map_err(|_| SearchSyntaxError::new("IP 地址格式无效", 0, 0))?
                        .to_string(),
                );
            }
        }
        let positive = if normalized.len() == 1 {
            json!({"term": {"ip": normalized.remove(0)}})
        } else {
            json!({"terms": {"ip": normalized}})
        };
        Ok(negative_filter(operator, "ip", positive, false))
    }

    fn compile_integer(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if matches!(operator, Operator::Contains | Operator::NotContains) {
            return Err(unsupported_operator(field));
        }
        let mut parsed_values = Vec::with_capacity(values.len());
        for value in values {
            let parsed = value.parse::<i64>().map_err(|_| {
                SearchSyntaxError::new(format!("{} 必须是数字", field.display_name()), 0, 0)
            })?;
            if field == Field::Port && !(1..=65_535).contains(&parsed) {
                return Err(SearchSyntaxError::new("端口必须在 1 到 65535 之间", 0, 0));
            }
            if field == Field::OsScore && !(0..=100).contains(&parsed) {
                return Err(SearchSyntaxError::new(
                    "os.score 必须在 0 到 100 之间",
                    0,
                    0,
                ));
            }
            if field == Field::TagId && parsed <= 0 {
                return Err(SearchSyntaxError::new("tag.id 必须是正整数", 0, 0));
            }
            parsed_values.push(parsed);
        }
        let name = es_field(field);
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            if parsed_values.len() != 1 {
                return Err(unsupported_operator(field));
            }
            let range_operator = match operator {
                Operator::Greater => "gt",
                Operator::GreaterEq => "gte",
                Operator::Less => "lt",
                Operator::LessEq => "lte",
                _ => unreachable!(),
            };
            return Ok(json!({"range": {(name): {(range_operator): parsed_values[0]}}}));
        }
        let positive = if parsed_values.len() == 1 {
            json!({"term": {(name): parsed_values[0]}})
        } else {
            json!({"terms": {(name): parsed_values}})
        };
        Ok(negative_filter(
            operator,
            name,
            positive,
            field == Field::TagId,
        ))
    }

    fn compile_time(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if values.len() != 1
            || !matches!(
                operator,
                Operator::Eq
                    | Operator::NotEq
                    | Operator::Greater
                    | Operator::GreaterEq
                    | Operator::Less
                    | Operator::LessEq
            )
        {
            return Err(unsupported_operator(field));
        }
        let value = normalize_time(&values[0])?;
        let name = es_field(field);
        if matches!(operator, Operator::Eq | Operator::NotEq) {
            let positive = json!({"term": {(name): value}});
            return Ok(negative_filter(operator, name, positive, false));
        }
        let range_operator = match operator {
            Operator::Greater => "gt",
            Operator::GreaterEq => "gte",
            Operator::Less => "lt",
            Operator::LessEq => "lte",
            _ => unreachable!(),
        };
        Ok(json!({"range": {(name): {(range_operator): value}}}))
    }

    fn compile_text(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            return Err(unsupported_operator(field));
        }
        for value in values {
            validate_text_value(field, value)?;
        }
        let name = es_field(field);
        let contains = matches!(operator, Operator::Contains | Operator::NotContains);
        let exact_keyword = matches!(
            field,
            Field::Protocol
                | Field::Service
                | Field::OsFamily
                | Field::OsDistribution
                | Field::OsVersion
                | Field::OsConfidence
                | Field::OsStatus
                | Field::Country
                | Field::Source
                | Field::Tag
                | Field::TagKind
                | Field::TagCategory
                | Field::TlsMode
                | Field::TlsVersion
                | Field::TlsCipherSuite
                | Field::TlsNames
                | Field::TlsSerialNumber
                | Field::TlsFingerprintSha256
        );
        let normalized_values = values
            .iter()
            .map(|value| {
                let value = if field == Field::Asn {
                    value
                        .strip_prefix("AS")
                        .or_else(|| value.strip_prefix("as"))
                        .unwrap_or(value)
                } else {
                    value
                };
                if exact_keyword && !contains {
                    value.to_lowercase()
                } else {
                    value.to_owned()
                }
            })
            .collect::<Vec<_>>();
        let positive = if contains || !exact_keyword {
            let wildcard_name = es_contains_field(field);
            let clauses = normalized_values
                .iter()
                .map(|value| {
                    let escaped = escape_es_wildcard(value);
                    let pattern = if contains {
                        format!("*{escaped}*")
                    } else {
                        escaped
                    };
                    json!({"wildcard": {(wildcard_name): {"value": pattern, "case_insensitive": true}}})
                })
                .collect::<Vec<_>>();
            if clauses.len() == 1 {
                clauses.into_iter().next().expect("one wildcard clause")
            } else {
                json!({"bool": {"should": clauses, "minimum_should_match": 1}})
            }
        } else if normalized_values.len() == 1 {
            json!({"term": {(name): normalized_values[0]}})
        } else {
            json!({"terms": {(name): normalized_values}})
        };
        let missing_matches_negative =
            matches!(field, Field::Tag | Field::TagKind | Field::TagCategory);
        Ok(negative_filter(
            operator,
            name,
            positive,
            missing_matches_negative,
        ))
    }

    fn compile_boolean(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if values.len() != 1 || !matches!(operator, Operator::Eq | Operator::NotEq) {
            return Err(unsupported_operator(field));
        }
        let value = values[0].parse::<bool>().map_err(|_| {
            SearchSyntaxError::new(
                format!("{} 只支持 true 或 false", field.display_name()),
                0,
                0,
            )
        })?;
        let name = es_field(field);
        Ok(negative_filter(
            operator,
            name,
            json!({"term": {(name): value}}),
            false,
        ))
    }
}

fn negative_filter(
    operator: Operator,
    field: &str,
    positive: Value,
    missing_matches: bool,
) -> Value {
    if !matches!(
        operator,
        Operator::NotEq | Operator::NotContains | Operator::NotIn
    ) {
        return positive;
    }
    if missing_matches {
        json!({"bool": {"must_not": [positive]}})
    } else {
        json!({"bool": {"filter": [{"exists": {"field": field}}], "must_not": [positive]}})
    }
}

fn es_field(field: Field) -> &'static str {
    match field {
        Field::Ip => "ip",
        Field::Domain => "domain",
        Field::Asn => "asn",
        Field::Isp => "isp",
        Field::Org => "as_org",
        Field::Country => "country_code",
        Field::City => "city_name",
        Field::Tag => "tag_names",
        Field::TagId => "tag_ids",
        Field::TagKind => "tag_kinds",
        Field::TagCategory => "tags.category_name",
        Field::Port => "port",
        Field::Protocol => "protocol",
        Field::Service => "service",
        Field::Banner => "banner",
        Field::OsFamily => "os.family",
        Field::OsDistribution => "os.distribution",
        Field::OsVersion => "os.version",
        Field::OsConfidence => "os.confidence",
        Field::OsStatus => "os.status",
        Field::OsScore => "os.score",

        Field::Title => "title",
        Field::HttpBody => "http_body",
        Field::TlsMode => "tls_mode",
        Field::TlsVersion => "tls_version",
        Field::TlsCipherSuite => "tls_cipher_suite",
        Field::TlsSubject => "tls_subject",
        Field::TlsIssuer => "tls_issuer",
        Field::TlsNames => "tls_names",
        Field::TlsSerialNumber => "tls_serial_number",
        Field::TlsNotBefore => "tls_not_before",
        Field::TlsNotAfter => "tls_not_after",
        Field::TlsFingerprintSha256 => "tls_fingerprint_sha256",
        Field::TlsSelfSigned => "tls_self_signed",
        Field::Source => "source",
        Field::Scanner => "scanner_name",
        Field::FirstSeen => "first_seen",
        Field::LastSeen => "last_seen",
    }
}

fn es_contains_field(field: Field) -> &'static str {
    match field {
        Field::Title => "title_contains",
        Field::HttpBody => "http_body_contains",
        _ => es_field(field),
    }
}

fn escape_es_wildcard(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
}

impl Field {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ip" | "network" => Some(Self::Ip),
            "domain" | "dns.domain" => Some(Self::Domain),
            "asn" => Some(Self::Asn),
            "isp" => Some(Self::Isp),
            "org" | "as_org" => Some(Self::Org),
            "country" | "country_code" => Some(Self::Country),
            "city" | "city_name" => Some(Self::City),
            "tag" => Some(Self::Tag),
            "tag.id" => Some(Self::TagId),
            "tag.kind" => Some(Self::TagKind),
            "tag.category" => Some(Self::TagCategory),
            "port" => Some(Self::Port),
            "protocol" => Some(Self::Protocol),
            "service" => Some(Self::Service),
            "banner" => Some(Self::Banner),
            "os.family" | "service.os.family" => Some(Self::OsFamily),
            "os.distribution" | "service.os.distribution" => Some(Self::OsDistribution),
            "os.version" | "service.os.version" => Some(Self::OsVersion),
            "os.confidence" | "service.os.confidence" => Some(Self::OsConfidence),
            "os.status" | "service.os.status" => Some(Self::OsStatus),
            "os.score" | "service.os.score" => Some(Self::OsScore),

            "title" | "http.title" => Some(Self::Title),
            "http_body" | "http.body" => Some(Self::HttpBody),
            "tls.mode" => Some(Self::TlsMode),
            "tls.version" => Some(Self::TlsVersion),
            "tls.cipher" | "tls.cipher_suite" => Some(Self::TlsCipherSuite),
            "tls_subject" | "tls.subject" => Some(Self::TlsSubject),
            "tls.issuer" => Some(Self::TlsIssuer),
            "tls.names" | "tls.san" => Some(Self::TlsNames),
            "tls.serial" | "tls.serial_number" => Some(Self::TlsSerialNumber),
            "tls.not_before" => Some(Self::TlsNotBefore),
            "tls.not_after" => Some(Self::TlsNotAfter),
            "tls.fingerprint" | "tls.fingerprint_sha256" => Some(Self::TlsFingerprintSha256),
            "tls.self_signed" => Some(Self::TlsSelfSigned),
            "source" => Some(Self::Source),
            "scanner" | "scanner_name" => Some(Self::Scanner),
            "first_seen" => Some(Self::FirstSeen),
            "last_seen" => Some(Self::LastSeen),
            _ => None,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Asn => "asn",
            Self::Isp => "isp",
            Self::Org => "org",
            Self::Country => "country",
            Self::City => "city",
            Self::Tag => "tag",
            Self::TagId => "tag.id",
            Self::TagKind => "tag.kind",
            Self::TagCategory => "tag.category",
            Self::Port => "port",
            Self::Protocol => "protocol",
            Self::Service => "service",
            Self::Banner => "banner",
            Self::OsFamily => "os.family",
            Self::OsDistribution => "os.distribution",
            Self::OsVersion => "os.version",
            Self::OsConfidence => "os.confidence",
            Self::OsStatus => "os.status",
            Self::OsScore => "os.score",

            Self::Title => "title",
            Self::HttpBody => "http_body",
            Self::TlsMode => "tls.mode",
            Self::TlsVersion => "tls.version",
            Self::TlsCipherSuite => "tls.cipher",
            Self::TlsSubject => "tls_subject",
            Self::TlsIssuer => "tls.issuer",
            Self::TlsNames => "tls.names",
            Self::TlsSerialNumber => "tls.serial",
            Self::TlsNotBefore => "tls.not_before",
            Self::TlsNotAfter => "tls.not_after",
            Self::TlsFingerprintSha256 => "tls.fingerprint",
            Self::TlsSelfSigned => "tls.self_signed",
            Self::Source => "source",
            Self::Scanner => "scanner",
            Self::FirstSeen => "first_seen",
            Self::LastSeen => "last_seen",
        }
    }

    fn is_endpoint(self) -> bool {
        matches!(
            self,
            Self::Port
                | Self::Protocol
                | Self::Service
                | Self::Banner
                | Self::OsFamily
                | Self::OsDistribution
                | Self::OsVersion
                | Self::OsConfidence
                | Self::OsStatus
                | Self::OsScore
                | Self::Title
                | Self::HttpBody
                | Self::TlsMode
                | Self::TlsVersion
                | Self::TlsCipherSuite
                | Self::TlsSubject
                | Self::TlsIssuer
                | Self::TlsNames
                | Self::TlsSerialNumber
                | Self::TlsNotBefore
                | Self::TlsNotAfter
                | Self::TlsFingerprintSha256
                | Self::TlsSelfSigned
                | Self::Source
        )
    }

    fn default_colon_operator(self) -> Operator {
        match self {
            Self::Service
            | Self::Banner
            | Self::Title
            | Self::HttpBody
            | Self::TlsSubject
            | Self::TlsIssuer
            | Self::TlsNames
            | Self::Isp
            | Self::Org
            | Self::City
            | Self::Scanner => Operator::Contains,
            Self::Domain => Operator::Contains,
            Self::OsFamily
            | Self::OsDistribution
            | Self::OsVersion
            | Self::OsConfidence
            | Self::OsStatus
            | Self::OsScore
            | Self::Ip
            | Self::Asn
            | Self::Country
            | Self::Tag
            | Self::TagId
            | Self::TagKind
            | Self::TagCategory
            | Self::Port
            | Self::Protocol
            | Self::TlsMode
            | Self::TlsVersion
            | Self::TlsCipherSuite
            | Self::TlsSerialNumber
            | Self::TlsNotBefore
            | Self::TlsNotAfter
            | Self::TlsFingerprintSha256
            | Self::TlsSelfSigned
            | Self::Source
            | Self::FirstSeen
            | Self::LastSeen => Operator::Eq,
        }
    }
}

fn parse_expression(query: &str) -> Result<(Expr, &str), SearchSyntaxError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(SearchSyntaxError::new("请输入搜索内容", 0, 0));
    }
    if query.chars().count() > MAX_QUERY_LENGTH {
        return Err(SearchSyntaxError::new(
            format!("查询内容不能超过 {MAX_QUERY_LENGTH} 个字符"),
            0,
            query.len(),
        ));
    }

    let expression = if let Ok(ip) = IpAddr::from_str(query) {
        Expr::Predicate(Predicate {
            field: Field::Ip,
            operator: Operator::Eq,
            values: vec![ip.to_string()],
        })
    } else if query.contains('/') {
        match normalize_network(query) {
            Ok(network) => Expr::Predicate(Predicate {
                field: Field::Ip,
                operator: Operator::In,
                values: vec![network],
            }),
            Err(_) => Parser::new(tokenize(query)?).parse()?,
        }
    } else {
        Parser::new(tokenize(query)?).parse()?
    };

    Ok((expression, query))
}

fn tokenize(input: &str) -> Result<Vec<Token>, SearchSyntaxError> {
    let mut tokens = Vec::new();
    let mut iter = input.char_indices().peekable();
    while let Some((start, ch)) = iter.next() {
        if ch.is_whitespace() {
            continue;
        }
        let single = |kind, end| Token { kind, start, end };
        match ch {
            '(' => tokens.push(single(TokenKind::LeftParen, start + 1)),
            ')' => tokens.push(single(TokenKind::RightParen, start + 1)),
            ',' => tokens.push(single(TokenKind::Comma, start + 1)),
            '=' => tokens.push(single(TokenKind::Eq, start + 1)),
            '!' => {
                let Some((next_index, next)) = iter.next() else {
                    return Err(SearchSyntaxError::new(
                        "! 后必须是 = 或 ~",
                        start,
                        start + 1,
                    ));
                };
                let kind = match next {
                    '=' => TokenKind::NotEq,
                    '~' => TokenKind::NotContains,
                    _ => {
                        return Err(SearchSyntaxError::new(
                            "! 后必须是 = 或 ~",
                            start,
                            next_index + next.len_utf8(),
                        ));
                    }
                };
                tokens.push(single(kind, next_index + next.len_utf8()));
            }
            '~' => tokens.push(single(TokenKind::Contains, start + 1)),
            '>' | '<' => {
                let mut end = start + 1;
                let has_equal = iter.peek().is_some_and(|(_, value)| *value == '=');
                if has_equal && let Some((index, value)) = iter.next() {
                    end = index + value.len_utf8();
                }
                let kind = match (ch, has_equal) {
                    ('>', true) => TokenKind::GreaterEq,
                    ('>', false) => TokenKind::Greater,
                    ('<', true) => TokenKind::LessEq,
                    ('<', false) => TokenKind::Less,
                    _ => unreachable!(),
                };
                tokens.push(single(kind, end));
            }
            '\'' | '"' => {
                let quote = ch;
                let mut value = String::new();
                let mut end = None;
                while let Some((index, current)) = iter.next() {
                    if current == quote {
                        end = Some(index + current.len_utf8());
                        break;
                    }
                    if current == '\\' {
                        let Some((_, escaped)) = iter.next() else {
                            return Err(SearchSyntaxError::new(
                                "字符串末尾不能是转义符",
                                start,
                                input.len(),
                            ));
                        };
                        value.push(escaped);
                    } else {
                        value.push(current);
                    }
                }
                let Some(end) = end else {
                    return Err(SearchSyntaxError::new(
                        "字符串缺少结束引号",
                        start,
                        input.len(),
                    ));
                };
                tokens.push(Token {
                    kind: TokenKind::String(value),
                    start,
                    end,
                });
            }
            _ => {
                let mut end = start + ch.len_utf8();
                while let Some((index, next)) = iter.peek().copied() {
                    if next.is_whitespace()
                        || matches!(
                            next,
                            '(' | ')' | ',' | '=' | '!' | '~' | '>' | '<' | '\'' | '"'
                        )
                    {
                        break;
                    }
                    iter.next();
                    end = index + next.len_utf8();
                }
                tokens.push(Token {
                    kind: TokenKind::Word(input[start..end].to_owned()),
                    start,
                    end,
                });
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse(mut self) -> Result<Expr, SearchSyntaxError> {
        if self.tokens.is_empty() {
            return Err(SearchSyntaxError::new("请输入搜索内容", 0, 0));
        }
        let expression = self.parse_or(0)?;
        if let Some(token) = self.peek() {
            return Err(SearchSyntaxError::new(
                "条件之间需要使用 AND 或 OR",
                token.start,
                token.end,
            ));
        }
        Ok(expression)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        let mut expression = self.parse_and(depth)?;
        while self.consume_keyword("OR") {
            let right = self.parse_and(depth)?;
            expression = Expr::Or(Box::new(expression), Box::new(right));
        }
        Ok(expression)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        let mut expression = self.parse_unary(depth)?;
        while self.consume_keyword("AND") {
            let right = self.parse_unary(depth)?;
            expression = Expr::And(Box::new(expression), Box::new(right));
        }
        Ok(expression)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        if self.consume_keyword("NOT") {
            return Ok(Expr::Not(Box::new(self.parse_unary(depth + 1)?)));
        }
        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        if self.consume_kind(&TokenKind::LeftParen) {
            let expression = self.parse_or(depth + 1)?;
            self.expect_kind(&TokenKind::RightParen, "缺少右括号 )")?;
            return Ok(expression);
        }
        if self.consume_keyword("EXISTS") {
            self.expect_kind(&TokenKind::LeftParen, "EXISTS 后需要左括号 (")?;
            let (field_name, token) = self.expect_word("EXISTS 中需要字段名")?;
            let field = Field::parse(&field_name).ok_or_else(|| {
                SearchSyntaxError::new(format!("不支持字段 {field_name}"), token.start, token.end)
            })?;
            self.expect_kind(&TokenKind::RightParen, "EXISTS 缺少右括号 )")?;
            return Ok(Expr::Predicate(Predicate {
                field,
                operator: Operator::Exists,
                values: Vec::new(),
            }));
        }
        if self.consume_keyword("HAS_ENDPOINT") {
            self.expect_kind(&TokenKind::LeftParen, "has_endpoint 后需要左括号 (")?;
            let expression = self.parse_or(depth + 1)?;
            self.expect_kind(&TokenKind::RightParen, "has_endpoint 缺少右括号 )")?;
            return Ok(Expr::HasEndpoint(Box::new(expression)));
        }
        self.parse_predicate()
    }

    fn parse_predicate(&mut self) -> Result<Expr, SearchSyntaxError> {
        let (first, first_token) = self.expect_word("这里需要字段名")?;
        if let Some((field_name, shorthand_value)) = first.split_once(':')
            && let Some(field) = Field::parse(field_name)
        {
            let value = if shorthand_value.is_empty() {
                self.expect_value("冒号后需要搜索值")?
            } else {
                shorthand_value.to_owned()
            };
            return Ok(Expr::Predicate(Predicate {
                field,
                operator: Operator::Colon,
                values: vec![value],
            }));
        }

        let field = Field::parse(&first).ok_or_else(|| {
            SearchSyntaxError::new(
                format!("不支持字段 {first}"),
                first_token.start,
                first_token.end,
            )
        })?;
        let operator = self.parse_operator()?;
        let values = if operator == Operator::Exists {
            Vec::new()
        } else if matches!(operator, Operator::In | Operator::NotIn) {
            self.parse_in_values()?
        } else {
            vec![self.expect_value("操作符后需要搜索值")?]
        };
        Ok(Expr::Predicate(Predicate {
            field,
            operator,
            values,
        }))
    }

    fn parse_operator(&mut self) -> Result<Operator, SearchSyntaxError> {
        let Some(token) = self.next().cloned() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new("字段后缺少操作符", end, end));
        };
        let operator = match &token.kind {
            TokenKind::Eq => Operator::Eq,
            TokenKind::NotEq => Operator::NotEq,
            TokenKind::Contains => Operator::Contains,
            TokenKind::NotContains => Operator::NotContains,
            TokenKind::Greater => Operator::Greater,
            TokenKind::GreaterEq => Operator::GreaterEq,
            TokenKind::Less => Operator::Less,
            TokenKind::LessEq => Operator::LessEq,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("IN") => Operator::In,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("EXISTS") => Operator::Exists,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("NOT") => {
                if self.consume_keyword("IN") {
                    Operator::NotIn
                } else {
                    return Err(SearchSyntaxError::new(
                        "字段后的 NOT 只能用于 NOT IN",
                        token.start,
                        token.end,
                    ));
                }
            }
            _ => {
                return Err(SearchSyntaxError::new(
                    "不支持的操作符",
                    token.start,
                    token.end,
                ));
            }
        };
        Ok(operator)
    }

    fn parse_in_values(&mut self) -> Result<Vec<String>, SearchSyntaxError> {
        if !self.consume_kind(&TokenKind::LeftParen) {
            return Ok(vec![self.expect_value("IN 后需要值或值列表")?]);
        }
        let mut values = Vec::new();
        loop {
            if self.consume_kind(&TokenKind::RightParen) {
                if values.is_empty() {
                    let end = self
                        .tokens
                        .get(self.position.saturating_sub(1))
                        .map(|v| v.end)
                        .unwrap_or(0);
                    return Err(SearchSyntaxError::new(
                        "IN 列表不能为空",
                        end.saturating_sub(1),
                        end,
                    ));
                }
                break;
            }
            values.push(self.expect_value("IN 列表中需要值")?);
            if self.consume_kind(&TokenKind::Comma) {
                continue;
            }
            self.expect_kind(&TokenKind::RightParen, "IN 列表缺少右括号 )")?;
            break;
        }
        if values.len() > MAX_IN_VALUES {
            return Err(SearchSyntaxError::new(
                format!("IN 列表最多包含 {MAX_IN_VALUES} 个值"),
                0,
                0,
            ));
        }
        Ok(values)
    }

    fn expect_value(&mut self, message: &str) -> Result<String, SearchSyntaxError> {
        let Some(token) = self.next() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new(message, end, end));
        };
        match &token.kind {
            TokenKind::Word(value) | TokenKind::String(value) => Ok(value.clone()),
            _ => Err(SearchSyntaxError::new(message, token.start, token.end)),
        }
    }

    fn expect_word(&mut self, message: &str) -> Result<(String, Token), SearchSyntaxError> {
        let Some(token) = self.next().cloned() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new(message, end, end));
        };
        match &token.kind {
            TokenKind::Word(value) => Ok((value.clone(), token)),
            _ => Err(SearchSyntaxError::new(message, token.start, token.end)),
        }
    }

    fn ensure_depth(&self, depth: usize) -> Result<(), SearchSyntaxError> {
        if depth <= MAX_DEPTH {
            return Ok(());
        }
        let token = self.peek();
        Err(SearchSyntaxError::new(
            format!("查询嵌套不能超过 {MAX_DEPTH} 层"),
            token.map(|value| value.start).unwrap_or(0),
            token.map(|value| value.end).unwrap_or(0),
        ))
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let matches = self.peek().is_some_and(|token| {
            matches!(&token.kind, TokenKind::Word(value) if value.eq_ignore_ascii_case(keyword))
        });
        if matches {
            self.position += 1;
        }
        matches
    }

    fn consume_kind(&mut self, kind: &TokenKind) -> bool {
        let matches = self.peek().is_some_and(|token| &token.kind == kind);
        if matches {
            self.position += 1;
        }
        matches
    }

    fn expect_kind(&mut self, kind: &TokenKind, message: &str) -> Result<(), SearchSyntaxError> {
        if self.consume_kind(kind) {
            return Ok(());
        }
        let token = self.peek();
        Err(SearchSyntaxError::new(
            message,
            token
                .map(|value| value.start)
                .unwrap_or_else(|| self.tokens.last().map(|value| value.end).unwrap_or(0)),
            token
                .map(|value| value.end)
                .unwrap_or_else(|| self.tokens.last().map(|value| value.end).unwrap_or(0)),
        ))
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.position);
        if token.is_some() {
            self.position += 1;
        }
        token
    }
}

fn normalize_network(value: &str) -> Result<String, SearchSyntaxError> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err(SearchSyntaxError::new("CIDR 必须包含前缀长度", 0, 0));
    };
    let ip = IpAddr::from_str(ip)
        .map_err(|_| SearchSyntaxError::new("CIDR 中的 IP 地址格式无效", 0, 0))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| SearchSyntaxError::new("CIDR 前缀长度格式无效", 0, 0))?;
    let network = IpNet::new(ip, prefix)
        .map_err(|_| SearchSyntaxError::new("CIDR 前缀长度超出范围", 0, 0))?;
    Ok(network.trunc().to_string())
}

fn normalize_time(value: &str) -> Result<String, SearchSyntaxError> {
    if let Some(relative) = value.strip_prefix("now-") {
        if relative.len() < 2 {
            return Err(SearchSyntaxError::new(
                "相对时间格式无效，例如 now-7d",
                0,
                0,
            ));
        }
        let (amount, unit) = relative.split_at(relative.len() - 1);
        let amount = amount
            .parse::<i64>()
            .map_err(|_| SearchSyntaxError::new("相对时间格式无效，例如 now-7d", 0, 0))?;
        if amount <= 0 {
            return Err(SearchSyntaxError::new("相对时间必须大于 0", 0, 0));
        }
        let duration = match unit {
            "m" => Duration::try_minutes(amount),
            "h" => Duration::try_hours(amount),
            "d" => Duration::try_days(amount),
            "w" => Duration::try_weeks(amount),
            _ => {
                return Err(SearchSyntaxError::new(
                    "相对时间单位只支持 m、h、d、w",
                    0,
                    0,
                ));
            }
        }
        .ok_or_else(|| SearchSyntaxError::new("相对时间超出允许范围", 0, 0))?;
        return Utc::now()
            .checked_sub_signed(duration)
            .map(|time| time.to_rfc3339())
            .ok_or_else(|| SearchSyntaxError::new("相对时间超出允许范围", 0, 0));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.to_rfc3339())
        .map_err(|_| SearchSyntaxError::new("时间必须是 RFC 3339 或 now-7d 格式", 0, 0))
}

fn validate_text_value(field: Field, value: &str) -> Result<(), SearchSyntaxError> {
    let length = value.chars().count();
    let minimum = if matches!(
        field,
        Field::Banner | Field::Title | Field::HttpBody | Field::TlsSubject
    ) {
        2
    } else {
        1
    };
    if !(minimum..=128).contains(&length) {
        return Err(SearchSyntaxError::new(
            format!(
                "{} 的长度必须在 {minimum} 到 128 个字符之间",
                field.display_name()
            ),
            0,
            0,
        ));
    }
    if field == Field::TagKind && !matches!(value, "info" | "malicious" | "benign") {
        return Err(SearchSyntaxError::new(
            "tag.kind 只支持 info、malicious、benign",
            0,
            0,
        ));
    }
    if field == Field::Country && value.chars().count() != 2 {
        return Err(SearchSyntaxError::new("country 必须是两位国家代码", 0, 0));
    }
    Ok(())
}

fn normalize_domain(value: &str) -> Result<String, SearchSyntaxError> {
    crate::dns::canonical_domain(value)
        .map_err(|_| SearchSyntaxError::new("domain 必须是有效域名", 0, 0))
}

fn unsupported_operator(field: Field) -> SearchSyntaxError {
    SearchSyntaxError::new(
        format!("字段 {} 不支持该操作符", field.display_name()),
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::{ElasticsearchCompilation, parse_and_compile_elasticsearch};
    fn filter(query: &str) -> serde_json::Value {
        match parse_and_compile_elasticsearch(query).unwrap() {
            ElasticsearchCompilation::Supported(value)
            | ElasticsearchCompilation::RequiresElasticsearch(value) => value,
            ElasticsearchCompilation::Unsupported => panic!("unsupported query: {query}"),
        }
    }

    #[test]
    fn compiles_boolean_precedence_and_bound_values() {
        let value = filter("country = CN OR port = 443 AND service = \"https\"");
        let text = value.to_string();
        assert!(text.contains("should"));
        assert!(text.contains("443"));
        assert!(text.contains("https"));
    }

    #[test]
    fn supports_legacy_syntax_and_ipv6() {
        assert!(filter("service:https").to_string().contains("*https*"));
        assert!(filter("2001:db8::1").to_string().contains("2001:db8::1"));
    }

    #[test]
    fn normalizes_cidr_and_compiles_tag_existence() {
        let text = filter("ip IN 192.168.1.123/24 AND tag = \"生产环境\"").to_string();
        assert!(text.contains("192.168.1.0/24"));
        assert!(text.contains("生产环境"));
    }

    #[test]
    fn compiles_asset_level_endpoint_requirements() {
        let text = filter("has_endpoint(port = 80) AND has_endpoint(port = 443)").to_string();
        assert_eq!(text.matches("network_mapping_has_endpoint").count(), 2);
    }

    #[test]
    fn rejects_asset_fields_inside_endpoint_scope() {
        let error = parse_and_compile_elasticsearch("has_endpoint(tag = prod)")
            .expect_err("asset field must be rejected");
        assert!(error.message.contains("不能使用资产字段"));
    }

    #[test]
    fn reports_missing_boolean_operator() {
        let error = parse_and_compile_elasticsearch("port = 80 service = http")
            .expect_err("implicit boolean operator must be rejected");
        assert_eq!(error.message, "条件之间需要使用 AND 或 OR");
        assert!(error.start > 0);
    }

    #[test]
    fn accepts_many_flat_conditions_within_predicate_limit() {
        let query = (1..=20)
            .map(|port| format!("port != {port}"))
            .collect::<Vec<_>>()
            .join(" AND ");
        parse_and_compile_elasticsearch(&query)
            .expect("flat conditions are not nested expressions");
    }

    #[test]
    fn negative_tag_means_not_exists() {
        assert!(filter("tag != retired").to_string().contains("must_not"));
    }

    #[test]
    fn rejects_overflowing_relative_time_without_panicking() {
        let error = parse_and_compile_elasticsearch("last_seen >= now-9223372036854775807w")
            .expect_err("overflowing relative time must be rejected");
        assert_eq!(error.message, "相对时间超出允许范围");
    }

    #[test]
    fn keeps_search_values_as_literal_dsl_values() {
        let value = filter("service = \"https' OR TRUE --\"");
        assert!(value.to_string().contains("https' or true --"));
        assert!(value.get("term").is_some() || value.get("bool").is_some());
    }

    #[test]
    fn compiles_supported_queries_to_elasticsearch_filter_dsl() {
        let ElasticsearchCompilation::Supported(filter) = parse_and_compile_elasticsearch(
            "country = CN AND port = 443 AND banner ~ \"Hikvision\"",
        )
        .expect("Elasticsearch filter should compile") else {
            panic!("query should be supported by Elasticsearch");
        };
        let serialized = filter.to_string();
        assert!(serialized.contains("country_code"));
        assert!(serialized.contains("banner"));
        assert!(serialized.contains("*Hikvision*"));
    }

    #[test]
    fn compiles_cross_endpoint_and_not_queries_for_elasticsearch() {
        let ElasticsearchCompilation::Supported(has_endpoint) =
            parse_and_compile_elasticsearch("has_endpoint(port = 443)").unwrap()
        else {
            panic!("has_endpoint should be resolved by the Elasticsearch search service");
        };
        assert!(has_endpoint.get("network_mapping_has_endpoint").is_some());

        let ElasticsearchCompilation::Supported(not_exists) =
            parse_and_compile_elasticsearch("NOT EXISTS(banner)").unwrap()
        else {
            panic!("NOT EXISTS should compile to must_not");
        };
        assert!(not_exists.to_string().contains("must_not"));

        let ElasticsearchCompilation::Supported(complex_not) =
            parse_and_compile_elasticsearch("NOT (service = http AND port = 80)").unwrap()
        else {
            panic!("complex NOT should compile with De Morgan semantics");
        };
        let complex_not = complex_not.to_string();
        assert!(complex_not.contains("minimum_should_match"));
        assert!(complex_not.matches("must_not").count() >= 2);
    }

    #[test]
    fn compiles_domain_queries_as_elasticsearch_only_filters() {
        let ElasticsearchCompilation::RequiresElasticsearch(filter) =
            parse_and_compile_elasticsearch("domain = www.example.com AND port = 443")
                .expect("domain query should compile")
        else {
            panic!("domain query must require Elasticsearch");
        };
        assert_eq!(
            filter.pointer("/bool/filter/0/network_mapping_domain/operator"),
            Some(&serde_json::json!("eq"))
        );
        assert_eq!(
            filter.pointer("/bool/filter/0/network_mapping_domain/values/0"),
            Some(&serde_json::json!("www.example.com"))
        );

        let ElasticsearchCompilation::RequiresElasticsearch(negated) =
            parse_and_compile_elasticsearch("NOT domain ~ example.com").unwrap()
        else {
            panic!("negated domain query must require Elasticsearch");
        };
        assert!(negated.to_string().contains("network_mapping_domain"));
        assert!(!negated.to_string().contains("exists"));
    }

    #[test]
    fn rejects_invalid_or_unsupported_domain_queries() {
        let invalid = parse_and_compile_elasticsearch("domain = invalid_domain")
            .expect_err("invalid domain must be rejected");
        assert_eq!(invalid.message, "domain 必须是有效域名");

        let exists = parse_and_compile_elasticsearch("EXISTS(domain)")
            .expect_err("domain existence cannot be expanded safely");
        assert_eq!(exists.message, "字段 domain 不支持 EXISTS");

        let nested = parse_and_compile_elasticsearch("has_endpoint(domain = example.com)")
            .expect_err("domain is not an endpoint field");
        assert!(nested.message.contains("不能使用资产字段"));
    }

    #[test]
    fn supports_http_and_tls_search_fields() {
        let text = filter(
            "title ~ camera AND http.body ~ hikvision AND tls.subject ~ example \
             AND tls.issuer ~ example AND tls.san = mail.example.com \
             AND tls.mode = starttls AND tls.version = TLSv1.3",
        )
        .to_string();
        for field in [
            "title",
            "http_body",
            "tls_subject",
            "tls_issuer",
            "tls_names",
            "tls_mode",
            "tls_version",
        ] {
            assert!(text.contains(field));
        }
    }

    #[test]
    fn compiles_tls_certificate_dates_and_boolean_fields() {
        let text = filter(
            "tls.not_after < 2027-01-01T00:00:00Z AND tls.self_signed = false \
             AND tls.fingerprint = AABBCCDD",
        )
        .to_string();
        assert!(text.contains("tls_not_after"));
        assert!(text.contains("tls_self_signed"));
        assert!(text.contains("tls_fingerprint_sha256"));
    }

    #[test]
    fn compiles_tag_category_for_elasticsearch() {
        assert!(
            filter("tag.category = \"运行环境\"")
                .to_string()
                .contains("tags.category_name")
        );
    }

    #[test]
    fn documented_queries_compile() {
        let queries = [
            "ip IN 192.0.2.0/24 AND port IN (80, 443) AND service ~ \"http\" AND tag = \"生产环境\"",
            "country = CN AND service = \"https\" AND last_seen >= now-7d",
            "(country = CN OR country = SG) AND port = 443",
            "asn IN (4134, AS4837)",
            "ip = 2001:db8::10",
            "EXISTS(service) AND NOT EXISTS(banner)",
            "tag = \"公网\" AND tag = \"核心资产\"",
            "tag.category = \"运行环境\" AND tag = \"生产环境\"",
            "tag.kind IN (malicious, info)",
            "port = 80 AND has_endpoint(port = 443 AND service = \"https\")",
            "scanner ~ \"上海\" AND port = 443",
            "last_seen >= \"2026-08-01T00:00:00+08:00\"",
            "service IN (mysql, postgresql, mongodb, redis) OR port IN (3306, 5432, 27017, 6379)",
        ];

        for query in queries {
            parse_and_compile_elasticsearch(query).unwrap_or_else(|error| {
                panic!("documented query failed: {query}: {}", error.message)
            });
        }
    }
    #[test]
    fn os_fields_compile_on_endpoints_and_scores_are_bounded() {
        let compiled = parse_and_compile_elasticsearch(
            "service.os.family = windows AND os.confidence = medium AND os.score >= 60",
        )
        .unwrap();
        let text = format!("{compiled:?}");
        assert!(text.contains("os.family"));
        assert!(text.contains("os.score"));
        assert!(parse_and_compile_elasticsearch("os.score > 101").is_err());
        assert!(parse_and_compile_elasticsearch("has_endpoint(os.family = linux)").is_ok());
    }
}
