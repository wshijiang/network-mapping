# 搜索触发目标更新

管理员在「运行时配置 → 自动目标 → 搜索触发更新」启用此功能。默认关闭；数据有效期默认 7 天，同一用户、同一规范化目标的搜索生成冷却默认 1440 分钟。配置通过现有 `automatic_target` 运行时命名空间持久化，修改后新请求生效，不修改已有任务。

## 搜索与执行

Web 主动提交搜索时，`POST /api/search/v2` 增加 `generate_if_needed: true`。旧客户端缺省为 false，分页始终为 false；服务端还要求 offset 为 0。GET 搜索接口不创建任务。

支持单个明确 IP、域名，以及附带 AND 筛选的明确目标，例如：

- `192.0.2.10` 或 `ip = 192.0.2.10 AND port = 443`
- `domain = "www.example.com" AND service = https`

CIDR、多个目标条件、IN、OR、NOT、has_endpoint 和模糊目标匹配不触发生成。目标从搜索语法树提取；IP 标准化，域名大小写和末尾句点统一。筛选条件只影响搜索结果，任务使用自动目标的 common_ports、priority 和数据库中的默认扫描模式。

IP 必须在 automatic_target 的对应地址族授权范围内，排除范围优先；搜索开关独立于 IPv4/IPv6 周期生成开关。周期网段配置的现有校验仍适用。

域名须开启 domain_enabled，且未命中 dns_follow_up.excluded_domains。域名不再使用白名单。还须开启 DNS 后续扫描。系统创建现有 dns_records 任务，后续端口任务按 dns_follow_up 的授权范围筛选解析地址。任务使用扫描节点的默认 DNS 解析器。域名刷新只有在 DNS 执行成功且已生成的子任务全部成功后才有效；无可扫描地址的成功解析也算完成。

## 配置

以下为首次数据库初始化时的示例；已初始化环境应在 Web 修改运行时配置：

```toml
[automatic_target.search_generation]
enabled = false
stale_after_days = 7         # 1–3650 天
cooldown_minutes = 1440     # 1–525600 分钟
max_pending_tasks = 100     # 1–10000 个搜索来源的待执行实例
per_user_hourly_limit = 20  # 1–10000 个根任务，滚动一小时
domain_enabled = false
# 域名排除在 [dns_follow_up] 的 excluded_domains 管理。
# 旧 authorized_domains 不再使用；升级或恢复旧配置时 domain_enabled 会关闭。
```

## 判断、去重和故障行为

1. 搜索成功后，单独按目标查询可见的索引观测，不将附加筛选的空结果当作目标缺失。索引错误不创建任务。
2. 复用同一用户已有的兼容任务（相同扫描模式，端口字符串相同或全端口）；IP 支持已有网段覆盖，域名包括尚未结束的后续任务。
3. 查询兼容的成功执行和持久化成功状态。成功扫描 0 个端口仍算成功；失败、取消、部分上传不更新成功时间。
4. 无兼容历史的 IP 使用目标最新观测时间作为旧数据升级依据。域名不能以端口观测时间代替 DNS 完成时间。
5. 成功刷新距今不超过有效期则跳过；否则检查搜索生成冷却、全局待执行上限和用户滚动一小时额度。
6. PostgreSQL 事务内原子创建 scan_task、scan_task_execution、审计及冷却、额度记录。创建失败全部回滚。事务锁保证不同服务进程的搜索生成不会并发超额或重复创建。

去重按用户隔离，不返回其他用户任务。搜索任务归触发用户，task_source 为 search，generation_strategy 为 search_on_demand。任务列表与详情标记「搜索生成」，统计筛选支持 search。

删除任务不会移除目标冷却和小时额度。成功上传事务更新已跟踪目标的成功时间，任务删除后仍可判断已知的成功刷新。过期的小时额度记录在后续准入时清理。

搜索之间保证原子去重；同时进行的手动/周期网段创建不共享搜索准入锁，因此不保证消除它们与搜索任务的所有并发覆盖重叠。已有的同用户兼容任务会被复用。

生成判断最多等待 4 秒，不等待扫描完成；超时或异常仍返回原搜索结果，auto_generation.status 为 unavailable。提交确认丢失时任务可能已创建，重新搜索会通过数据库去重确认。

响应增加可选 auto_generation：status、reason、target、task_id、next_eligible_at。后者是 Unix 毫秒时间戳，与 scan_time 一致；仅表示冷却结束，届时仍需重新判断。状态为 disabled、unsupported、out_of_scope、fresh、created、existing、cooldown、queue_full、rate_limited 或 unavailable。

## 数据库与验证

启动时现有 init.sql 幂等建表流程新增 search_target_state、search_generation_admission 及索引。task_initiator 扩为 VARCHAR(200)，与用户名称长度一致，搜索生成保留真实操作者。

```sh
cargo fmt --check
cargo clippy --locked --all-targets
cargo test --locked
STORAGE_TEST_DATABASE_URL=postgresql://USER@HOST/TEST_DB cargo test --locked target_generated::search -- --ignored --test-threads=1
```

数据库测试在指定测试库中创建随机隔离 schema，正常完成后删除，仅应用于可丢弃测试数据库。覆盖 100 个并发搜索、用户隔离、空结果成功、任务删除后的冷却、动态有效期、额度、创建失败回滚、DNS 子任务及网段覆盖。

## 域名排除与升级

`dns_follow_up.excluded_domains` 统一控制搜索、手工和 OpenAPI 的 DNS 任务；与解析后 IP 扫描的 enabled 开关独立。普通域名只精确排除，`*.example.com` 排除所有层级子域但不包含根域；要排除整个域树应同时填写两条。大小写、首尾空白和末尾根点被规范化。最多 256 条；不支持裸 `*`、`?`、任意位置 `*`、协议、路径或端口。

创建混合批次时任一域名被排除会拒绝整批，不静默丢目标。领取/恢复任务时 SQL 策略阻止被排除的任务及其 DNS 派生子任务；运行中任务在下一次心跳收到取消指令，已离开进程的网络请求无法撤回。DNS 结果仍可作为历史证据保存，但不会生成新的后续任务。共享 IP 不会因此成为全局 IP 排除项。

初始化会幂等迁移数据库中含旧 `authorized_domains` 的配置，保存新修订并关闭域名搜索生成；文件/env 和历史版本恢复也做相同的安全转换。旧白名单不会复制成排除列表。管理员配置排除规则后可以重新启用域名搜索生成。独立升级 SQL 为 `source/database/migrate_dns_domain_exclusions.sql`；降级前关闭域名自动生成并恢复配套配置与前端。

排除项在保存时规范化；任务领取端使用相同的 Unicode 空白和尾点规则。直接写入数据库的无效排除列表会阻止 DNS 任务领取，避免忽略损坏策略。
