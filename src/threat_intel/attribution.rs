//! Human attribution decisions live separately from immutable model evidence.
use super::*;
use deadpool_postgres::Transaction;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ActorDecision {
    Keep,
    Unassigned,
    Select { actor_id: String },
    Alias { actor_id: String },
    Create { name: String },
}

pub(super) async fn candidates(pool: &Pool, id: Uuid) -> Result<Value> {
    let c = pool.get().await?;
    let row = c
        .query_opt(
            "SELECT source_id,payload FROM intel_record WHERE id=$1",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    let source: Uuid = row.get(0);
    let payload: Value = row.get(1);
    let name = payload["actor_name"].as_str().unwrap_or("").trim();
    let rows=c.query("SELECT e.attack_id,e.name,e.dataset_version,CASE WHEN m.id IS NOT NULL THEN 'source_alias' WHEN LOWER(e.name)=LOWER($2) THEN 'exact_name' ELSE 'associated_name' END AS basis FROM intel_entity e LEFT JOIN intel_name_mapping m ON m.attack_id=e.attack_id AND m.source_id=$1 AND m.kind='actor' AND m.name_normalized=LOWER($2) WHERE e.active AND e.kind='actor' AND $2<>'' AND (m.id IS NOT NULL OR LOWER(e.name)=LOWER($2) OR EXISTS(SELECT 1 FROM unnest(e.aliases) a WHERE LOWER(a)=LOWER($2))) ORDER BY (m.id IS NOT NULL) DESC,(LOWER(e.name)=LOWER($2)) DESC,e.attack_id LIMIT 20",&[&source,&name]).await?;
    Ok(
        json!({"report_name":name,"items":rows.iter().map(|r|json!({"attack_id":r.get::<_,String>(0),"name":r.get::<_,String>(1),"dataset_version":r.get::<_,String>(2),"basis":r.get::<_,String>(3)})).collect::<Vec<_>>()}),
    )
}

pub(super) async fn decide(
    tx: &Transaction<'_>,
    row: &tokio_postgres::Row,
    decision: Option<&ActorDecision>,
    user: &UserBaseI,
) -> Result<Value> {
    let decision = decision.unwrap_or(&ActorDecision::Keep);
    let source: Uuid = row.get("source_id");
    let payload: Value = row.get("payload");
    let report = payload["actor_name"].as_str().unwrap_or("").trim();
    let mut action = "keep";
    let actor_id: Option<String> = match decision {
        ActorDecision::Unassigned => {
            action = "unassigned";
            None
        }
        ActorDecision::Keep => {
            let saved: Option<String> = row.get("actor_id");
            if saved.is_some() {
                saved
            } else {
                let rows=tx.query("SELECT e.attack_id FROM intel_entity e WHERE e.active AND e.kind='actor' AND $2<>'' AND (LOWER(e.name)=LOWER($2) OR EXISTS(SELECT 1 FROM intel_name_mapping m WHERE m.source_id=$1 AND m.kind='actor' AND m.name_normalized=LOWER($2) AND m.attack_id=e.attack_id)) ORDER BY e.attack_id LIMIT 2",&[&source,&report]).await?;
                (rows.len() == 1).then(|| rows[0].get(0))
            }
        }
        ActorDecision::Select { actor_id } | ActorDecision::Alias { actor_id } => {
            if report.is_empty() || actor_id.len() > 100 {
                return Err(Error::bad("intel_invalid_attribution"));
            }
            if !tx.query_one("SELECT EXISTS(SELECT 1 FROM intel_entity WHERE attack_id=$1 AND kind='actor' AND active)",&[actor_id]).await?.get::<_,bool>(0){return Err(Error::bad("intel_unknown_actor"));}
            action = if matches!(decision, ActorDecision::Alias { .. }) {
                "alias"
            } else {
                "select"
            };
            if action == "alias" {
                tx.execute("INSERT INTO intel_name_mapping(id,source_id,name_normalized,attack_id,reviewed_by,kind) VALUES($1,$2,LOWER($3),$4,$5,'actor') ON CONFLICT(source_id,name_normalized,kind) DO UPDATE SET attack_id=EXCLUDED.attack_id,reviewed_by=EXCLUDED.reviewed_by,created_at=NOW()",&[&Uuid::now_v7(),&source,&report,actor_id,&user.id]).await?;
            }
            Some(actor_id.clone())
        }
        ActorDecision::Create { name } => {
            let name = name.trim();
            if report.is_empty()
                || name.is_empty()
                || name.len() > 200
                || name.chars().any(char::is_control)
            {
                return Err(Error::bad("intel_invalid_attribution"));
            }
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended(LOWER($1),318))",
                &[&name],
            )
            .await?;
            if tx.query_one("SELECT EXISTS(SELECT 1 FROM intel_entity WHERE kind='actor' AND active AND LOWER(name)=LOWER($1))",&[&name]).await?.get::<_,bool>(0){return Err(Error::bad("intel_actor_name_exists"));}
            let uid = Uuid::now_v7();
            let id = format!("LOCAL-G-{uid}");
            let stix = format!("local-intrusion-set--{uid}");
            let object = json!({"type":"intrusion-set","name":name,"origin":"human_review","report_name":report});
            tx.execute("INSERT INTO intel_entity(attack_id,stix_id,kind,name,source_id,dataset_version,object) VALUES($1,$2,'actor',$3,$4,'local-reviewed',$5)",&[&id,&stix,&name,&source,&object]).await?;
            action = "create";
            Some(id)
        }
    };
    Ok(json!({"action":action,"actor_id":actor_id,"report_name":report}))
}
