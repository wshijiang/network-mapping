//! Bounded immutable discovery snapshots, separate from DNS resource records.
use super::*;
use crate::domain_discovery::Evidence;
impl ElasticsearchService {
    fn discovery_index(&self) -> String {
        format!("{}-discovery-v1", self.inner.config.dns_record_index)
    }
    pub(crate) async fn discovery_write(
        &self,
        id: Uuid,
        owner: i32,
        attempt: i64,
        evidence: &Evidence,
    ) -> Result<(), String> {
        if !self.enabled() {
            return Err("discovery storage unavailable".into());
        }
        let index = self.discovery_index();
        self.ensure_named_index(&index,&json!({"settings":{"number_of_replicas":self.inner.config.scan_number_of_replicas},"mappings":{"dynamic":"strict","properties":{
            "owner_id":{"type":"integer"},"seed":{"type":"keyword"},"names":{"type":"keyword"},"fetched_at":{"type":"date"},"evidence":{"type":"object","enabled":false}
        }}})).await?;
        let doc = json!({"owner_id":owner,"seed":evidence.seed,"names":evidence.candidates.iter().map(|c|&c.name).collect::<Vec<_>>(),"fetched_at":evidence.fetched_at,"evidence":evidence});
        self.send_json_request(
            ElasticsearchOperation::BulkWrite,
            Method::PUT,
            &format!(
                "/{index}/_doc/{id}?refresh=wait_for&version={attempt}&version_type=external_gte"
            ),
            |r| r.json(&doc),
        )
        .await
        .map(|_| ())
    }
    pub(crate) async fn discovery_read(&self, id: Uuid, owner: i32) -> Result<Evidence, String> {
        let doc = self
            .send_json_request(
                ElasticsearchOperation::DomainFilter,
                Method::GET,
                &format!("/{}/_doc/{id}", self.discovery_index()),
                |r| r,
            )
            .await?;
        if doc.pointer("/_source/owner_id").and_then(Value::as_i64) != Some(i64::from(owner)) {
            return Err("not found".into());
        }
        serde_json::from_value(doc["_source"]["evidence"].clone())
            .map_err(|_| "invalid discovery evidence".into())
    }
    pub(crate) async fn discovery_relations(
        &self,
        owner: i32,
        domain: &str,
    ) -> Result<Value, String> {
        let result=self.send_json_request(ElasticsearchOperation::DomainFilter,Method::POST,&format!("/{}/_search?ignore_unavailable=true",self.discovery_index()),|r|r.json(&json!({"size":20,"track_total_hits":true,"sort":[{"fetched_at":"desc"}],"query":{"bool":{"filter":[{"term":{"owner_id":owner}}],"should":[{"term":{"names":domain}},{"term":{"seed":domain}},{"wildcard":{"names":format!("*.{domain}")}}],"minimum_should_match":1}}}))).await?;
        validate_scan_search_response(&result)?;
        Ok(result)
    }
}
