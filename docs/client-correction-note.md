# Draft: correction note to the client

Send in week 0. Plain email, no attachments beyond the corrected chart if they want it. Adjust the greeting and sign-off.

---

Subject: Two corrections to the CPDPM benchmark report

Hi [name],

While preparing the CPDPM work for further study I re-ran the benchmark suite I delivered to you and found two things in the report that I want to correct.

**1. The "Security vs Performance Trade-off" chart.** The security scores in that chart (AES-256 at 85, CPDPM at 95, RSA at 90) were placeholder values in the plotting code, not measured results. I should have caught that before it went out. Please disregard that one chart. The other performance charts are measured.

**2. The CPDPM-versus-AES timing ratio.** The report shows CPDPM at roughly 2x the cost of plain AES-256. That figure is a measurement artifact: the CPDPM decryption timing included the password key-derivation step while the AES baseline reused an already-derived key. Measured on equal terms, encryption and decryption times are within a few percent of plain AES-256.

**What this means for you.** The protection your data receives is unchanged and is sound: AES-256 with a random IV, HMAC-SHA256 integrity checking, and PBKDF2 key derivation. What changes is how I would describe the extra polynomial step. It is a reversible byte transform applied before encryption; it does not add cryptographic strength beyond what AES-256 already provides, and I no longer describe it as a second security layer.

I am now developing a successor design that binds each encrypted record to its patient, tenant and field so that a record cannot be silently moved between them. I would be glad to share that when it is ready, and if you would like the two charts regenerated with corrected data I can send them this week.

Apologies for the errors, and thank you for your patience.

[signature]
