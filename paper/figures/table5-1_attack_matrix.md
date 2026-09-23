| Scheme | Correct row | Patient swap | Tenant move | Field move | Stale replay |
|---|---|---|---|---|---|
| AES-256-CBC + HMAC, one shared key | accepted | accepted | accepted | accepted | n/a |
| AES-256-GCM, key per tenant, no AAD | accepted | accepted | rejected | accepted | n/a |
| CPDPM (this work) | accepted | rejected | rejected | rejected | rejected |
| CPDPM FHIR layer | accepted | rejected | – | – | – |
