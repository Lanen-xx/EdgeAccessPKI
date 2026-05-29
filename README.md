# EdgeAccessPKI

EdgeAccessPKI 是面向工业现场维护窗口的边缘准入网关。系统使用 TinyPKI v1.0.0 作为底层 PKI 核心，在维护命令进入产线控制侧之前完成证书、撤销状态、发证记录和 witness 门限验证。

工业现场常见问题是维护终端、边缘网关和受控设备之间存在弱连接、离线窗口和临时授权。EdgeAccessPKI 将 CA checkpoint、2-of-2 witness 策略、ECQV 证书、撤销证明和发证证明绑定到命令验证流程中。命令在证书有效、未撤销、发证记录可信且 witness 门限满足时放行；证书撤销后，即使终端继续提交旧证据，网关也会拒绝。

## Product Shape

EdgeAccessPKI 不是最小样例程序。仓库包含可执行网关、站点配置、访问策略、安装规则、CI、部署说明和运维手册。程序读取 `config/gateway.conf`，可输出人类可读日志，也可通过 `--json` 输出结构化准入结果，方便接入工业日志平台、边缘网关控制面或维护工单系统。

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target edge_access_pki -j 2
./build/edge_access_pki --config config/gateway.conf
```

本地联调 TinyPKI 源码时可使用：

```bash
cmake -S . -B build -DEDGEACCESSPKI_TINY_PKI_PATH=/path/to/TinyPKI
```

默认发布依赖固定到 TinyPKI v1.0.0。

## Runtime

```bash
./build/edge_access_pki --config config/gateway.conf --json
```

典型输出包含工业 CA 初始化、维护终端证书签发、2-of-2 checkpoint 导入、签名维护命令放行、证书撤销、撤销后旧命令拒绝。结构化结果示例：

```json
{"product":"EdgeAccessPKI","site":"plant-east","line":"line-ctrl-07","terminal":"MAINT-TERMINAL-17","decision_before_revocation":"ALLOW","decision_after_revocation":"DENY","required_witnesses":2,"fail_closed":true}
```

## Deployment Files

- `config/gateway.conf`：站点、产线、终端、控制器、命令和 witness 门限策略。
- `config/access_policy.csv`：维护终端、角色、产线、允许命令和时间窗口。
- `docs/deployment.md`：边缘网关部署方式。
- `docs/operator_runbook.md`：维护窗口运行、审计和故障处理流程。
- `docs/security_model.md`：信任边界、准入条件和拒绝条件。

## Safety Defaults

EdgeAccessPKI 默认按失败闭锁运行。配置文件缺失时使用内置安全默认值并打印警告；证据包缺失、checkpoint 过期、witness 门限不足、证书撤销或命令超出策略时，网关保持拒绝状态。边缘网关负责执行验证和准入，不保存或托管 CA 私钥。
