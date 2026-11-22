//! 目标监控：周期复扫 + 基线 diff + 变化通知。与系统健康 `monitor` 模块相互独立。
pub mod diff;
mod routes;
mod rules;
mod worker;

pub use routes::configure;
pub(crate) use worker::run;
#[cfg(test)]
mod tests;
