# Deployment

EdgeAccessPKI 部署在工业边缘网关或维护隔离区入口处。它位于维护终端和产线控制器之间，先验证身份与状态，再把准入结果交给上层网关策略执行。

## Components

- Industrial CA：签发维护终端和现场控制器证书，发布 checkpoint。
- Plant Witnesses：两个独立边缘 witness 对 checkpoint 签名，形成 2-of-2 策略。
- EdgeAccessPKI：验证维护命令、证据包和 witness 门限。
- Gateway Adapter：根据 EdgeAccessPKI 输出的 `ALLOW` 或 `DENY` 控制命令转发。

## Install

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target install
```

安装后默认配置目录为 `etc/edgeaccesspki`。站点配置应由运维平台下发，访问策略应与维护工单系统保持一致。

## Runtime Contract

EdgeAccessPKI 输出的准入结果可以被工业网关直接消费：

- `ALLOW`：维护终端证书有效，证据包通过，witness 门限满足，命令处于允许策略内。
- `DENY`：任一安全条件失败，网关不得转发维护命令。
- `WARN`：配置缺省、运行环境不完整或需要运维确认。

程序不负责控制物理执行器，只负责把 PKI 证据转化为边缘准入决策。
