# Access Policy

EdgeAccessPKI 把维护准入拆成三类检查：

- 身份检查：维护终端必须持有工业 CA 签发的 ECQV 证书。
- 状态检查：证据包中的撤销证明必须绑定到网关已接受的 checkpoint。
- 发布检查：发证证明必须证明该证书进入 CA 的发证记录，并满足 witness 门限策略。

边缘网关不接受终端自称的状态，也不接受边缘缓存直接给出的结论。所有结论都来自本地验证。

本应用使用 2-of-2 witness 策略。两个 witness 都签过同一 checkpoint 时，网关才接受该 checkpoint。
