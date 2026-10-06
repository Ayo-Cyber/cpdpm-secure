| Scheme | Correct row | Patient swap | Tenant move | Field move | Stale replay |
|---|---|---|---|---|---|
| AES-256-CBC + HMAC, one shared key | accepted | accepted | accepted | accepted | n/a |
| AES-256-GCM, key per tenant, context as AAD | accepted | rejected | rejected | rejected | n/a |
| AES-256-GCM, key per tenant, no AAD | accepted | accepted | rejected | accepted | n/a |
| CPDPM (this work) | accepted | rejected | rejected | rejected | rejected |
| CPDPM FHIR layer | accepted | rejected | – | – | – |

Leaked-key exposure (one cell's key leaked; cells it opens):

| Scheme | Cells opened | Patients | Tenants |
|---|---|---|---|
| AES-256-CBC + HMAC, one shared key | 200/200 | 100 | 2 |
| AES-256-GCM, key per tenant, context as AAD | 100/200 | 50 | 1 |
| AES-256-GCM, key per tenant, no AAD | 100/200 | 50 | 1 |
| CPDPM (this work) | 1/200 | 1 | 1 |
