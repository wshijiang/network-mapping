//! scan_control / creation domain implementation, migrated from the library root.

use deadpool_postgres::GenericClient;
use ipnet::{AddrParseError, IpNet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::target::{TargetIP, check_port, parsing_target};
use crate::{admin, audit};

/// 该结构体用于接收用户创建任务时的数据
/// 仅有三个参数
#[derive(Deserialize)]
pub struct CreateTask {
    pub ip: String,
    pub port: String,
    pub level: i8,
    pub remark: Option<String>,
    #[serde(default = "default_dispatch_mode")]
    pub dispatch_mode: String,
    #[serde(default)]
    pub scanner_ids: Vec<Uuid>,
    #[serde(default)]
    pub scan_profile: Option<String>,
}

pub(crate) fn default_dispatch_mode() -> String {
    "automatic".into()
}

pub fn build_scan_plan(profile: &str) -> Result<Value, &'static str> {
    let stages = match profile {
        "legacy" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": false}
        ]),
        "port_only" => serde_json::json!([
            {"type": "port_discovery", "required": true}
        ]),
        "service_inventory" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": true}
        ]),
        "vulnerability_scan" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": false},
            {"type": "vulnerability_detection", "required": true}
        ]),
        "dns_records" => serde_json::json!([
            {"type": "dns_lookup", "required": true}
        ]),
        "dns_ports" => serde_json::json!([
            {"type": "dns_lookup", "required": true},
            {"type": "port_discovery", "required": true}
        ]),
        "dns_full" => serde_json::json!([
            {"type": "dns_lookup", "required": true},
            {"type": "port_discovery", "required": true}
        ]),
        _ => return Err("unsupported scan profile"),
    };
    Ok(serde_json::json!({
        "version": 1,
        "profile": profile,
        "stages": stages,
    }))
}

/// Profiles valid for IP/CIDR tasks and the system-wide default. DNS profiles
/// require the dedicated domain-task endpoint and must never be inherited by
/// an IP task.
pub fn is_ip_scan_profile(profile: &str) -> bool {
    matches!(
        profile,
        "legacy" | "port_only" | "service_inventory" | "vulnerability_scan"
    )
}

/// Returns the profile selected by the user for display purposes. A domain
/// follow-up request keeps `dns_records` as its executable parent profile and
/// stores the requested IP profile in generation metadata.
pub fn display_scan_profile(stored_profile: &str, generation_metadata: Option<&Value>) -> String {
    generation_metadata
        .and_then(|metadata| metadata.pointer("/dns_follow_up/scan_profile"))
        .and_then(Value::as_str)
        .filter(|profile| is_ip_scan_profile(profile))
        .unwrap_or(stored_profile)
        .to_owned()
}

/// 该结构体用于表示一个任务，该结构体不适合直接接收用户创建任务时的数据
#[derive(Serialize)]
pub struct CreatedTasks {
    pub task_ids: Vec<String>,
    pub task_group_id: Option<Uuid>,
}

pub struct STask<'a> {
    pub task_id: Option<uuid::Uuid>,
    pub task_initiator: &'a str,
    pub ip: Vec<IpNet>,
    // u16 刚好 0~65535，如果不提供则默认为全端口，当然可以在配置文件中配置默认端口
    pub port: Option<&'a str>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remark: Option<&'a str>,
}

impl STask<'_> {
    pub fn address_family(&self) -> Result<&'static str, &'static str> {
        let has_ipv4 = self.ip.iter().any(|target| matches!(target, IpNet::V4(_)));
        let has_ipv6 = self.ip.iter().any(|target| matches!(target, IpNet::V6(_)));
        match (has_ipv4, has_ipv6) {
            (true, false) => Ok("ipv4"),
            (false, true) => Ok("ipv6"),
            (true, true) => Err("同一扫描任务不能混合 IPv4 和 IPv6 目标"),
            (false, false) => Err("扫描目标不能为空"),
        }
    }
}

impl<'a> STask<'a> {
    pub fn new(
        ip: TargetIP,
        initiator: &'a str,
        port: Option<&'a str>,
        remark: Option<&'a str>,
    ) -> Result<Self, AddrParseError> {
        let t_ip = parsing_target(ip)?;

        let t_port = match port {
            Some(p) if check_port(p) => p,
            Some(_) => "1-65535",
            None => "1-65535",
        };
        Ok(Self {
            task_id: Some(Uuid::now_v7()),
            task_initiator: initiator,
            ip: t_ip,
            port: Some(t_port),
            start_at: None,
            end_at: None,
            remark,
        })
    }

    /// 用于向数据库中添加一条扫描任务条目
    /// 返回一个 Result，当执行成功时返回 OK
    #[allow(clippy::too_many_arguments)]
    pub async fn add(
        &self,
        pool: &deadpool_postgres::Pool,
        level: i32,
        user_id: i32,
        dispatch_mode: &str,
        requested_scanners: &[Option<String>],
        scan_profile: &str,
        scan_plan: &Value,
        audit_context: &audit::AuditContext,
        actor: &admin::UserBaseI,
        maxmind: &crate::maxmind::MaxMindState,
    ) -> Result<CreatedTasks, Box<dyn std::error::Error>> {
        let mut p = pool.get().await?;
        let client = p.transaction().await?;
        let t_id = self
            .task_id
            .map(|task_id| task_id.to_string())
            .ok_or("task_id 为 None")?;

        let address_family = self.address_family()?;
        let groups = if dispatch_mode == "automatic"
            && super::routing::config(&client)
                .await
                .map_err(std::io::Error::other)?
                .enabled
        {
            super::routing::group_targets(&self.ip, |net| {
                super::routing::target_geo(&[net.to_string()], maxmind)
            })
        } else {
            vec![self.ip.clone()]
        };
        let group_id = (groups.len() > 1).then(Uuid::now_v7);
        let mut task_ids = Vec::new();
        for (index, group) in groups.iter().enumerate() {
            let public_id = if index == 0 {
                t_id.clone()
            } else {
                Uuid::now_v7().to_string()
            };
            task_ids.push(public_id.clone());
            let targets: Vec<String> = group.iter().map(ToString::to_string).collect();
            let task_db_id:i32 = client.query_one(
                "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, dispatch_mode, address_family, scan_profile, scan_plan, task_group_id) \
                 VALUES ($1,$2,$3,ARRAY(SELECT inet(unnest($4::text[]))),$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id",
                &[&user_id,&public_id,&self.task_initiator,&targets,&self.port,&level,&self.remark,&dispatch_mode,&address_family,&scan_profile,&scan_plan,&group_id]
            ).await?.get("id");
            for requested_scanner in requested_scanners {
                client.execute("INSERT INTO scan_task_execution(execution_id,task_id,requested_scanner_id) VALUES($1,$2,$3)", &[&Uuid::now_v7().to_string(),&task_db_id,requested_scanner]).await?;
            }
            let mut event = audit::AuditEvent::user("task", "task.create", "success", actor)
                .resource("task", public_id);
            event.response_status = Some(200);
            event.metadata = serde_json::json!({"dispatch_mode":dispatch_mode,"scanner_count":requested_scanners.len(),"target_count":group.len(),"scan_profile":scan_profile,"task_group_id":group_id,"group_task_count":groups.len()});
            audit::write(&client, audit_context, &event).await?;
        }

        client.commit().await?;
        Ok(CreatedTasks {
            task_ids,
            task_group_id: group_id,
        })
    }
}
