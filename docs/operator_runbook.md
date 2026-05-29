# Operator Runbook

## Before Maintenance Window

1. 确认 `config/gateway.conf` 中的站点、产线、维护终端和控制器编号。
2. 确认 `config/access_policy.csv` 中存在对应维护工单的允许命令。
3. 确认两个 plant witness 均完成 checkpoint 签名。
4. 执行 `edge_access_pki --config config/gateway.conf --json` 做维护前自检。

## During Maintenance

网关侧只接受 EdgeAccessPKI 输出的结构化准入结果：

- `decision_before_revocation=ALLOW`：维护窗口内可以放行该命令。
- `decision_after_revocation=DENY`：撤销后旧证据已失效，应拒绝继续操作。
- `required_witnesses=2`：当前策略要求两个 witness 均参与。

## Incident Handling

证书撤销、证据包篡改、witness 不足、checkpoint 回滚或命令超出策略，都应登记为维护安全事件。现场恢复应通过 CA 发布新 checkpoint 和更新访问策略完成，不应手工修改网关二进制或绕过准入结果。
