# Run Result

The following result was produced with:

```bash
./build-product-mingw/edge_access_pki.exe --config config/gateway.conf --json
```

Key events:

```text
[OK] load gateway configuration
[OK] enforce 2-of-2 plant policy
[INFO] site=plant-east line=line-ctrl-07 terminal=MAINT-TERMINAL-17 controller=LINE-CTRL-07
[OK] import 2-of-2 checkpoint
[OK] accept signed maintenance command
[OK] encode portable evidence
[OK] revoke maintenance terminal
[OK] reject command after revocation
```

Structured decision:

```json
{"product":"EdgeAccessPKI","site":"plant-east","line":"line-ctrl-07","terminal":"MAINT-TERMINAL-17","decision_before_revocation":"ALLOW","decision_after_revocation":"DENY","required_witnesses":2,"fail_closed":true}
```

The result matches an industrial maintenance gate: a valid maintenance terminal is accepted during the authorized window, and the same terminal is rejected after revocation even if it keeps presenting old evidence.
