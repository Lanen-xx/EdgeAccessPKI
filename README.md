# EdgeAccessPKI

EdgeAccessPKI 是一个工业现场边缘准入应用。它使用 TinyPKI v1.0.0 管理维护终端、现场设备和边缘网关之间的身份关系，使维护命令在进入设备侧之前先完成证书、撤销状态和发证记录验证。

场景设定为一条生产线的维护窗口：维护终端向边缘网关提交签名命令，网关持有 CA checkpoint 和 witness 策略，并在本地完成验证。命令通过时，网关放行；证书被撤销后，即使终端继续提交旧证据，网关也会拒绝。

## 场景链路

1. 工业 CA 为维护终端和受控设备签发 ECQV 证书。
2. 两个边缘 witness 对 CA checkpoint 签名，形成 2-of-2 策略。
3. 维护终端提交维护命令、签名和证据包。
4. 边缘网关验证证书、撤销证明、发证证明和 witness 签名。
5. 终端证书被撤销后，网关导入新 checkpoint。
6. 旧命令和旧证据被拒绝。

## 运行结果

```text
[OK] issue maintenance terminal certificate
[OK] issue line controller certificate
[OK] import 2-of-2 checkpoint
[OK] accept signed maintenance command
[OK] encode portable evidence
[OK] revoke maintenance terminal
[OK] import post-revocation checkpoint
[OK] reject command after revocation
```

## 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target edge_access_pki -j 2
./build/edge_access_pki
```

本仓库固定使用 TinyPKI v1.0.0。
