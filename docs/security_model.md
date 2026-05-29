# Security Model

EdgeAccessPKI 的信任基础由工业 CA 公钥、CA 签名 checkpoint、两个 plant witness、访问策略和本地时间窗口组成。维护终端提交的命令必须携带可验证证据，网关只在所有条件通过后输出 `ALLOW`。

## Admission Requirements

- 维护终端证书由可信工业 CA 签发。
- 证书未被当前撤销状态拒绝。
- 发证证明进入 CA 发布的发证记录。
- checkpoint 由 CA 签名，并满足 2-of-2 witness 策略。
- 命令与 `access_policy.csv` 中的终端、产线和维护窗口匹配。

## Rejection Cases

系统按失败闭锁处理以下情况：

- 证据包字段缺失、编码异常或被篡改。
- checkpoint 低于本地已见版本或超过允许窗口。
- witness 重复、门限不足或密钥版本不匹配。
- 维护终端证书被撤销。
- 命令不在当前维护策略中。

## Operational Notes

配置文件不保存私钥。CA 私钥和 witness 私钥应由站点密钥管理系统或硬件安全模块保护。EdgeAccessPKI 的职责是边缘准入判断，最终设备控制仍由工业网关和现场安全系统执行。
