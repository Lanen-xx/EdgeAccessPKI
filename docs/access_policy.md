# Access Policy

EdgeAccessPKI 把维护准入拆成三类检查：

- 身份检查：维护终端必须持有工业 CA 签发的 ECQV 证书。
- 状态检查：证据包中的撤销证明必须绑定到网关已接受的 checkpoint。
- 发布检查：发证证明必须证明该证书进入 CA 的发证记录，并满足 witness 门限策略。

边缘网关不接受终端自称的状态，也不接受边缘缓存直接给出的结论。所有结论都来自本地验证。

本应用使用 2-of-2 witness 策略。两个 witness 都签过同一 checkpoint 时，网关才接受该 checkpoint。

生产部署中，`config/access_policy.csv` 应由维护工单系统生成，至少包含终端编号、角色、产线编号、允许命令和维护窗口。EdgeAccessPKI 会把策略配置与 PKI 证据一起纳入准入判断，避免维护命令只通过证书验证就进入设备侧。
