# Rust 业务模块进程替换原型

[完整方案](../../MODULAR_ARCHITECTURE.md)

本例使用真实的两个 Rust 二进制版本，通过父子进程 stdin/stdout 管道通信，不需要数据库、网络监听、Cargo 依赖或服务端配置。宿主进程与服务端代码无集成；用于验证热更新生命周期。

v1 的示例计算返回输入数值；v2 通过编译条件加入不同的计算代码，返回输入数值乘十。此计算仅用于清晰辨认执行版本，并非正式报表统计公式。

## 自动验证

从服务端仓库根目录执行，要求 Rust 编译器和 Python 3：

```sh
python3 docs/examples/modular-hot-update/verify.py
```

Rust 编译器不在 PATH 时：

```sh
python3 docs/examples/modular-hot-update/verify.py --rustc /absolute/path/to/rustc
```

脚本在临时目录编译、运行并清理制品，检查：

- v1 的慢请求固定旧版本，v2 激活后新请求在新版本完成。
- 不匹配的发布 revision 被拒绝。
- 协议不兼容、制品版本不匹配及非启动允许列表中的制品被拒绝。
- 候选失败后原活跃版本仍可处理请求。
- 回滚到 v1 时 revision 继续递增。
- 退出与候选拒绝时，已启动子进程经过 kill/wait 回收。

## 手动演示

```sh
rustc --edition=2024 docs/examples/modular-hot-update/prototype.rs -o /tmp/nm-module-v1
rustc --edition=2024 --cfg enhanced docs/examples/modular-hot-update/prototype.rs -o /tmp/nm-module-v2
/tmp/nm-module-v1 host /tmp/nm-module-v1 /tmp/nm-module-v2
```

向宿主标准输入逐行输入：

```text
ACTIVATE 0 /tmp/nm-module-v1 v1
CALL 1 1000 2
ACTIVATE 1 /tmp/nm-module-v2 v2
CALL 2 0 2
```

可看到请求 1 固定 revision 1/v1，最终返回 2；请求 2 固定 revision 2/v2，返回 20。两个请求完成的先后取决于输入时间；自动验证使用握手确认旧请求已取得句柄。

回滚与退出：

```text
ACTIVATE 2 /tmp/nm-module-v1 v1
CALL 3 0 2
QUIT
```

回滚创建 revision 3；旧请求仍持有旧 worker 的 `Arc`，最后一个持有者释放后才回收子进程。宿主退出先等待请求线程，再回收活跃 worker。

## 实现细节与局限

`Host::activate` 先检查 expectedRevision，再在锁外启动候选、握手、健康检查和自检，最后短锁内再次 CAS 并替换句柄。`Host::acquire` 在启动请求线程前取得固定的 revision/worker，避免线程调度导致请求切到另一版本。

`Worker` 的 I/O broker 用有界 channel 串行化请求与响应；超时会停止该 worker，避免误把迟到响应分配给下一请求。管道帧最多 1 KiB，最多 32 个宿主请求线程，每个请求等待最多三秒。只支持本文的可信演示制品与不含空格的文件路径；制品不应 fork 或把管道继承给其他进程。

原型在最后一个句柄释放时回收旧进程，回滚会重新启动旧制品；生产环境可以增加短时间保留旧版本的策略。原型的队列串行处理不适合高吞吐场景；生产需要并行请求 ID 分发、绝对 deadline、容量隔离、输出完整校验与进程监督。

候选和宿主之间的私有管道不对外提供 API。允许列表仅用于演示受控执行，不实现制品摘要、签名或防篡改。进程被外部强制杀死时的孤儿回收需要生产监督器；此例只覆盖正常退出和受控候选失败。

数据库长任务需要完整方案中的持久化租约与 token，不能用 `Arc` 引用计数替代。该独立原型不改变生产服务；实际已接入的报表渲染接口与部署边界见[实现说明](../../MODULE_RUNTIME_IMPLEMENTATION.md)。
