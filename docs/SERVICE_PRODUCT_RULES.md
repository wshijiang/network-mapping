# 服务产品规则包

[服务产品识别](SERVICE_PROTOCOLS.md#服务产品识别) · [搜索语法](SEARCH_SYNTAX.md)

服务端从规则 v6 起从 JSON 读取 Mythic、Empire / Starkiller 和 Sliver 的匹配条件。使用现有证据类型添加 C2 候选规则时，可以直接替换规则包并重启服务。Cobalt Strike、AsyncRAT / DcRAT 和 QakBot 继续由内置代码判定。内置 v7 收窄为 C2 候选，v8 增加内置 XMRig 声明判定。外部规则的证据来源及规则文件格式保持兼容。JARM 继续作为独立 TLS 观察。

## 导出、校验和启用

```bash
network_mapping_server product-rules export > builtin-product-rules.json
cp builtin-product-rules.json product-rules.json
# 修改 product-rules.json，并增加 ruleset_revision
network_mapping_server product-rules validate --file product-rules.json --against builtin-product-rules.json
network_mapping_server product-rules test --file product-rules.json --fixtures docs/examples/product-rules-fixtures.json
```

三个子命令可离线运行。省略 `--file` 时校验或回放内置包。在后续修改时，`--against` 使用上一份实际启用的规则包。校验输出修订号、条数和原始文件字节的 SHA-256。修改文件内容时应增加修订号，包括回退到先前条件的情况。

```toml
[product_rules]
file = "product-rules.json"
```

文件模式下，相对路径以配置文件所在目录为基准。环境模式使用 `NM__PRODUCT_RULES__FILE`，相对路径以进程工作目录为基准。容器中可将规则文件只读挂载。省略配置或使用空字符串时加载内置包。外部包替换内置可配置规则全集，保留现有规则时需将它们一并放入文件。显式配置的文件缺失或校验失败会阻止服务启动。

服务启动日志的 `ProductRulesLoaded` 事件包含来源、修订号、摘要和规则条数。将其与 `validate` 的结果核对。详情的 `product_identification.ruleset_revision` 与 `ruleset_sha256` 可核对实际执行过的规则包。

## 字段和条件

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 文件结构版本，当前为 `1` |
| `ruleset_revision` | 内容修订号，最小值为 `6` |
| `rules[].id` | 稳定的规则 ID，在包内唯一，直接进入候选证据 |
| `product` | 包含 `id`、`name` 和可选的 `component`，同一产品 ID 的名称和组件须一致 |
| `source` | `tls_leaf` 或 `http_management_page` |
| `basis` | 证书使用 `certificate_template` 或 `historical_certificate_heuristic`，管理页使用 `http_management_fingerprint` |
| `match` | 匹配条件树 |
| `references` | HTTPS 参考链接数组，第一项随证据展示 |
| `prefilter` | 可选的 HTTP 正文原始子串，区分大小写，用于跳过无关页面 |

产品 ID 和规则 ID 以小写字母开头，可包含小写字母、数字、下划线和连字符。内置 Rust 规则使用的产品 ID，以及已退役的 `nginx`、`apache_http_server`、`openssh`，均为保留 ID。

```json
{
  "all": [
    { "field": "subject_dn", "op": "eq", "value": "CN=Example Console" },
    {
      "any": [
        { "field": "issuer_dn", "op": "eq", "value": "CN=Example CA" },
        {
          "all": [
            { "field": "self_signed", "op": "eq", "value": false },
            { "field": "signature_algorithm", "op": "eq", "value": "ecdsa_sha256" }
          ]
        }
      ]
    },
    {
      "none": [
        { "field": "issuer_dn", "op": "eq", "value": "CN=Test CA" },
        { "field": "subject_dn", "op": "contains", "value": "Demo" }
      ]
    }
  ]
}
```

每个分组只能有一个 `all`、`any` 或 `none` 键，值为非空数组。这个示例等价于 `A AND (B OR (C AND D)) AND NOT (E OR F)`。缺失字段为未知。只要有明确为真的分支，`any` 就为真。只有每一条分支都明确为假，`none` 才为真。整个表达式为真时产生 `suspected` 候选。

普通条件用 `field` 和 `op`。等值 `eq` 使用 `value`，集合 `in` 使用 `values`。文本支持 `eq_ignore_ascii_case`、`contains` 和 `regex`。可选 `evidence_key` 用于设置证据摘要中的字段名称。

- `tls_leaf` 支持 `subject_dn`、`issuer_dn`、`self_signed`、`signature_algorithm`、`fingerprint_sha256` 和 `validity_end`。布尔字段使用 JSON 布尔值。证书摘要使用小写十六进制。ECDSA 别名规范为 `ecdsa_sha256`、`ecdsa_sha384` 或 `ecdsa_sha512`。
- `http_management_page` 支持 `title`、`element`、`element_text` 和 `element_attribute`。后三者需要 `selector`，属性条件还需要 `attribute`。`element` 只使用 `exists`。元素文本合并空白，多个符合选择器的元素中任意一个命中即可。元素存在性可由完整 DOM 判定。文本或属性取值缺失时按未知处理。
- 条件组始终在单一叶证书或单一管理页内求值。HTTP 响应完整性与同源检查由取证层执行。规则中的链接与标记只用于本地比对和解释。

## 回放和搜索验证

回放文件是 JSON 数组。每项含 `name`、原始 `data`、`expected_rule_ids` 和可选的 `observed_at`、`expected_status`、`expected_coverage`、`expected_paths`。预期规则 ID 列表按集合比较，未命中用空数组。命令列出候选组件、规则 ID 和原始路径，任何样本不符时返回非零退出码。仓库提供正负样本示例。[回放样本](examples/product-rules-fixtures.json)

新扫描使用启动时加载的规则。资产详情在原始证据仍可用时可按新规则重算。搜索读取已保存的投影，存量结果需用同一份规则包重建。重建期间固定进程内规则快照，续跑要求规则版本、摘要和内置判定逻辑版本与断点一致。旧版本已开始的重建应使用原程序完成后再升级。验证新增规则时核对 `product = 产品ID`，删除规则时核对旧候选已从重放后的投影消失。[投影升级与回滚](SERVICE_PROTOCOLS.md#存储升级与回滚)
