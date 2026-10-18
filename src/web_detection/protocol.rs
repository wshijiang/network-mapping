//! Bounded protocol markers. Never retain bucket names, refs, request IDs or bodies.
use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;

const S3_NAMESPACE: &[u8] = b"http://s3.amazonaws.com/doc/2006-03-01/";

pub(super) fn s3_xml_feature(body: &str) -> Option<String> {
    let mut reader = NsReader::from_str(body);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut root = String::new();
    let mut closed = false;
    let mut direct = std::collections::BTreeSet::new();
    let mut code = String::new();
    let mut in_code = false;
    let mut request_id_text = false;
    let mut in_request_id = false;
    for _ in 0..16_384 {
        let (namespace, event) = reader.read_resolved_event().ok()?;
        let empty = matches!(&event, Event::Empty(_));
        let namespaced = matches!(&namespace, ResolveResult::Bound(_));
        let allowed_namespace = match &namespace {
            ResolveResult::Bound(namespace) => namespace.as_ref() == S3_NAMESPACE,
            ResolveResult::Unbound => true,
            ResolveResult::Unknown(_) => return None,
        };
        match event {
            Event::DocType(_) => return None,
            Event::Start(element) | Event::Empty(element) => {
                let local = element.local_name();
                let local = std::str::from_utf8(local.as_ref()).ok()?;
                if !allowed_namespace || element.attributes().any(|a| a.is_err()) {
                    return None;
                }
                if depth == 0 {
                    if closed || !root.is_empty() {
                        return None;
                    }
                    if !matches!(
                        local,
                        "ListBucketResult" | "ListAllMyBucketsResult" | "Error"
                    ) || (local != "Error" && !namespaced)
                    {
                        return None;
                    }
                    root = local.into();
                } else if (root != "Error" && !namespaced)
                    || (depth >= 2 && (in_code || in_request_id))
                {
                    return None;
                } else if depth == 1 {
                    direct.insert(local.to_owned());
                    in_code = local == "Code";
                    in_request_id = local == "RequestId";
                }
                if empty {
                    if depth == 0 {
                        closed = true;
                    }
                    in_code = false;
                    in_request_id = false;
                } else {
                    depth += 1;
                    if depth > 32 {
                        return None;
                    }
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    closed = true;
                }
                if depth < 2 {
                    in_code = false;
                    in_request_id = false;
                }
            }
            Event::Text(text) => {
                let text = std::str::from_utf8(text.as_ref()).ok()?;
                if depth == 0 && !text.trim().is_empty() {
                    return None;
                }
                if depth == 2 && in_code {
                    if code.len() + text.len() > 128 {
                        return None;
                    }
                    code.push_str(text);
                }
                if depth == 2 && in_request_id && !text.trim().is_empty() {
                    request_id_text = true;
                }
            }
            Event::GeneralRef(reference) => {
                let entity: &[u8] = reference.as_ref();
                if depth == 0
                    || in_code
                    || !matches!(entity, b"amp" | b"lt" | b"gt" | b"quot" | b"apos")
                {
                    return None;
                }
            }
            Event::CData(_) => return None,
            Event::Eof => {
                if !closed || depth != 0 {
                    return None;
                }
                return match root.as_str() {
                    "ListBucketResult" if direct.contains("Name") && direct.contains("MaxKeys") => {
                        Some(root)
                    }
                    "ListAllMyBucketsResult" if direct.contains("Buckets") => Some(root),
                    "Error"
                        if request_id_text
                            && matches!(
                                code.trim(),
                                "AccessDenied"
                                    | "NoSuchBucket"
                                    | "NoSuchKey"
                                    | "InvalidAccessKeyId"
                                    | "SignatureDoesNotMatch"
                                    | "AuthorizationHeaderMalformed"
                                    | "RequestTimeTooSkewed"
                                    | "InvalidBucketName"
                                    | "MethodNotAllowed"
                            ) =>
                    {
                        Some(format!("Error/{}", code.trim()))
                    }
                    _ => None,
                };
            }
            _ => {}
        }
    }
    None
}

fn packet(input: &[u8]) -> Option<(usize, &[u8])> {
    let prefix = std::str::from_utf8(input.get(..4)?).ok()?;
    if !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let length = usize::from_str_radix(prefix, 16).ok()?;
    if length == 0 {
        return Some((4, &[]));
    }
    if !(4..=65_520).contains(&length) {
        return None;
    }
    Some((length, input.get(4..length)?))
}

pub(super) fn git_advertisement_feature(
    content_types: &[&str],
    body: &str,
) -> Option<&'static str> {
    let mut operations = std::collections::BTreeSet::new();
    for content_type in content_types {
        match content_type
            .split(';')
            .next()?
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "application/x-git-upload-pack-advertisement" => {
                operations.insert("git-upload-pack");
            }
            "application/x-git-receive-pack-advertisement" => {
                operations.insert("git-receive-pack");
            }
            _ => return None,
        }
    }
    if operations.len() != 1 {
        return None;
    }
    let operation = *operations.first()?;
    let (offset, first) = packet(body.as_bytes())?;
    let expected: &[u8] = if operation == "git-upload-pack" {
        b"# service=git-upload-pack\n"
    } else {
        b"# service=git-receive-pack\n"
    };
    if first == expected {
        return (body.as_bytes().get(offset..offset + 4) == Some(b"0000")).then_some(operation);
    }
    if first != b"version 2\n" || operation != "git-upload-pack" {
        return None;
    }
    let mut remaining = body.as_bytes().get(offset..)?;
    let mut fetch = false;
    let mut refs = false;
    for _ in 0..128 {
        let (offset, line) = packet(remaining)?;
        if line.is_empty() {
            return (fetch && refs).then_some(operation);
        }
        if !line.ends_with(b"\n") {
            return None;
        }
        fetch |= line == b"fetch\n" || line.starts_with(b"fetch=");
        refs |= line == b"ls-refs\n" || line.starts_with(b"ls-refs=");
        remaining = remaining.get(offset..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_structure_rejects_dtd_html_wrong_namespaces_and_incomplete_xml() {
        assert_eq!(s3_xml_feature(r#"<?xml version="1.0"?><!-- response --><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>PRIVATE</Name><MaxKeys>1000</MaxKeys></ListBucketResult>"#).as_deref(),Some("ListBucketResult"));
        for body in [
            r#"<ListBucketResult xmlns="urn:other"><Name>x</Name><MaxKeys>1</MaxKeys></ListBucketResult>"#,
            r#"<html><body>&lt;ListBucketResult&gt;</body></html>"#,
            r#"<!DOCTYPE Error [<!ENTITY external SYSTEM "file:///private">]><Error><Code>AccessDenied</Code><RequestId>&external;</RequestId></Error>"#,
            r#"<Error><Code>AccessDenied</Code><RequestId>x</RequestId>"#,
            r#"<Error><Code>AccessDenied</Code><RequestId>x</RequestId></Error><Other/>"#,
        ] {
            assert!(s3_xml_feature(body).is_none(), "{body}");
        }
    }

    #[test]
    fn git_markers_require_correlated_media_type_and_valid_packet_lengths() {
        let body = "001e# service=git-upload-pack\n0000";
        let upload = ["application/x-git-upload-pack-advertisement"];
        assert_eq!(
            git_advertisement_feature(&upload, body),
            Some("git-upload-pack")
        );
        assert!(git_advertisement_feature(&["text/html"], body).is_none());
        assert!(
            git_advertisement_feature(
                &["application/x-git-upload-pack-advertisement", "text/html"],
                body
            )
            .is_none()
        );
        assert!(
            git_advertisement_feature(&upload, "001f# service=git-upload-pack\n0000").is_none()
        );
        assert!(
            git_advertisement_feature(&upload, "001e# service=git-receive-pack\n0000").is_none()
        );
        assert!(git_advertisement_feature(&upload, "<p>git-upload-pack</p>").is_none());
        assert_eq!(
            git_advertisement_feature(
                &["application/x-git-receive-pack-advertisement"],
                "001f# service=git-receive-pack\n0000"
            ),
            Some("git-receive-pack")
        );
        let v2 = "000eversion 2\n000cls-refs\n000afetch\n0000";
        assert_eq!(
            git_advertisement_feature(&upload, v2),
            Some("git-upload-pack")
        );
        assert!(git_advertisement_feature(&upload, "000eversion 2\n0000").is_none());
    }
}
