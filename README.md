# EdgeAccessPKI

EdgeAccessPKI 是一套面向工业现场维护窗口的边缘准入系统。它使用 TinyPKI v1.0.0 作为底层 PKI 核心，在维护终端向产线控制侧发送命令之前完成证书、撤销状态、发证记录、CA checkpoint 和 witness 门限验证。

工业现场常见的准入风险来自弱连接、临时授权、离线维护窗口和边缘网关被误信任。EdgeAccessPKI 将 CA 签名 checkpoint、2-of-2 witness 策略、ECQV 证书、撤销证明和发证证明绑定到命令验证流程中。证书有效、未撤销、发证记录可信、witness 门限满足且命令落在策略窗口内时，网关放行维护命令；证书撤销、checkpoint 过期、证据不完整或命令越权时，网关保持拒绝状态。

## 应用场景

EdgeAccessPKI 适用于工厂产线维护、边缘控制柜、远程巡检终端、临时检修窗口和弱网工业园区。维护人员可以在授权时间窗口内使用终端访问指定产线控制器，边缘网关在现场完成本地判定，不依赖实时在线查询。

站点配置由 `config/gateway.conf` 描述，包含工厂站点、产线编号、维护终端、控制器、维护命令和 witness 门限。访问策略由 `config/access_policy.csv` 描述，记录终端角色、允许命令、维护窗口和策略状态。现场结果可以输出为结构化 JSON，供工业日志平台、运维工单系统或边缘控制面记录。

## 核心能力

- 维护终端 ECQV 身份证书导入和验证。
- CA 签名 checkpoint 本地导入和时间窗口检查。
- 双 witness 门限验证，约束单点边缘节点误放行。
- 撤销证明和发证证明联合验证。
- 维护命令与访问策略绑定检查。
- 撤销后旧命令自动拒绝。
- 缺少证据、状态过期或策略不匹配时失败闭锁。

## 准入决策

一次维护窗口会形成清晰的放行和拒绝结果：

```json
{"product":"EdgeAccessPKI","site":"plant-east","line":"line-ctrl-07","terminal":"MAINT-TERMINAL-17","decision_before_revocation":"ALLOW","decision_after_revocation":"DENY","required_witnesses":2,"fail_closed":true}
```

`decision_before_revocation` 为 `ALLOW` 表示维护终端证书、撤销状态、发证记录、checkpoint、witness 门限和命令策略均已通过。`decision_after_revocation` 为 `DENY` 表示同一终端证书被撤销后，旧证据和旧命令不再被接受，网关不会继续开放控制通道。

## 部署形态

系统由四个角色组成：

- Industrial CA：负责维护终端证书签发、撤销状态发布和 checkpoint 签名。
- Plant Witnesses：缓存 CA 状态，参与 checkpoint 见证，形成现场门限约束。
- EdgeAccessPKI Gateway：在边缘网关上执行证据验证、策略检查和准入决策。
- Control Plane Adapter：接收准入结果，控制维护命令进入产线控制侧。

部署和现场运行说明见 `docs/deployment.md`、`docs/operator_runbook.md` 和 `docs/security_model.md`。这些文档分别描述网关部署、维护窗口操作、异常处置和安全边界。

## TinyPKI在本系统中的作用

EdgeAccessPKI 固定使用 TinyPKI v1.0.0。TinyPKI 提供 ECQV 证书、稀疏 Merkle 撤销证明、发证记录证明、CA checkpoint、witness 门限和安全会话能力；EdgeAccessPKI 将这些能力组织成工业维护准入流程。

TinyPKI 承担底层信任与证据验证核心，EdgeAccessPKI 承担站点配置、策略绑定、准入判定、现场日志和控制面适配边界。
