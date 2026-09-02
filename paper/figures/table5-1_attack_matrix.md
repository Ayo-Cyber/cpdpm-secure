| Scheme | Correct row | Patient swap | Tenant move | Field move | Stale replay |
|---|---|---|---|---|---|
| AES-256-GCM, key per tenant, no AAD | accepted | accepted | rejected | accepted | accepted |
| CPDPM v2 (this work) | accepted | rejected | rejected | rejected | rejected |
| v1 (shipped client build) | accepted | accepted | accepted | accepted | accepted |
| CPDPM v2 FHIR layer | accepted | rejected | – | – | – |
