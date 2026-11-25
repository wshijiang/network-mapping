# 用户管理 CLI

服务端二进制不带子命令时仍按原方式启动 HTTPS 服务。以下命令连接 `--config` 指定的
PostgreSQL，完成操作后退出：

```sh
network_mapping_server --config config.toml user create alice --role user --email alice@example.com
network_mapping_server --config config.toml user password set alice
network_mapping_server --config config.toml user 2fa clear alice --yes
network_mapping_server --config config.toml user show alice --sessions active
```

源码构建环境可将上述 `network_mapping_server` 替换为 `cargo run --`。

## 密码与创建用户

`user create` 和 `user password set` 默认从终端隐藏读取密码并要求输入两次。密码长度为
12–256 个字符。不要在命令行参数中传递明文密码；自动化脚本应使用标准输入：

```sh
printf '%s\n' "$NEW_PASSWORD" | network_mapping_server user password set alice --password-stdin
```

也可以使用 `--generate` 生成随机密码。随机密码只在当前终端显示一次。修改密码会解除
密码错误锁定、重置错误次数，并使该用户现有会话全部失效。`user create --role` 接受 `admin`、`user`、`read-only` 和 `auditor`。
内部 system 用户由服务端管理。

## 角色与授权

使用 `user access show <用户名>` 查看角色、授权范围与版本。使用
`user access set` 更新普通、只读或审计账号，并提供当前版本、JSON 授权文件和变更原因。
可用权限和命令示例见[用户角色与权限管理](USER_ACCESS.md)。

## 2FA 与登录白名单

清除 2FA 是破坏性操作：

```sh
network_mapping_server user 2fa clear alice
network_mapping_server user 2fa clear alice --yes       # 非交互环境
```

该操作会删除 TOTP 密钥和待绑定密钥，并使现有会话失效。

登录白名单支持 IPv4、IPv6 和 CIDR：

```sh
network_mapping_server user allowlist list alice
network_mapping_server user allowlist add alice 192.0.2.10 10.0.0.0/8 2001:db8::/32
network_mapping_server user allowlist remove alice 192.0.2.10
network_mapping_server user allowlist remove alice 10.0.0.0/8 --ignore-missing
```

地址会规范化、排序和去重；单个地址显示为 `/32` 或 `/128`。空白名单表示不限制来源，
每个用户最多保存 64 条。删除操作按规范化后的网络精确匹配。

## 登录限制

一次可以处理一个或多个逗号分隔的用户：

```sh
network_mapping_server user login restrict --users alice,bob
network_mapping_server user login restrict --users alice,bob --dry-run
network_mapping_server user login unrestrict --users alice,bob
```

批量操作是原子的：用户名不存在时全部回滚。限制登录使用管理员禁用状态，不会篡改密码
错误锁定状态；限制时会使现有会话失效。系统拒绝限制最后一个仍可登录的管理员。

## 用户与登录记录查询

```sh
network_mapping_server user show alice --sessions active  # active、all 或 none
network_mapping_server user login-log alice --outcome failure --since 7d --limit 200
network_mapping_server user login-log alice --since 2026-09-01T00:00:00Z --format json --pager never
network_mapping_server user login-log alice --all --format csv --pager always
```

登录记录来自统一的 `audit_event`，支持 `--outcome success|failure`、RFC3339 起止时间，
以及 `Nd`、`Nh`、`Nm` 形式的相对起始时间。默认显示最新 100 条。表格超过 24 行且输出到
终端时会调用 `$PAGER`（默认 `less`）；JSON/CSV 可直接重定向。用户信息不会显示 session
token 或 CSRF token。

所有 CLI 写操作及登录记录读取都会写入审计表，操作者类型为 `system`、名称为 `cli`；
审计内容不包含明文密码、密码哈希、TOTP 密钥或会话令牌。
