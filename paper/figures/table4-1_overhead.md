| Plaintext | GCM blob | GCM text | XChaCha blob | XChaCha text | GCM stream (64 KiB chunks) |
|---:|---:|---:|---:|---:|---:|
| 0 B | +71 B | +102 B | +83 B | +118 B | +70 B |
| 64 B | +71 B | +123 B | +83 B | +139 B | +70 B |
| 726 B | +71 B | +344 B | +83 B | +360 B | +70 B |
| 6,761 B | +71 B | +2,356 B | +83 B | +2,372 B | +70 B |
| 67,113 B | +71 B | +22,473 B | +83 B | +22,489 B | +86 B |
| 669,830 B | +71 B | +223,379 B | +83 B | +223,395 B | +230 B |

Blob overhead is constant: 11-byte header + nonce (12 or 24) + 32-byte commitment + 16-byte tag. Text form adds the 7-byte `cpdpm1:` prefix and base64url expansion (one third of the blob). Stream overhead is 15 + prefix + 32 + 16 bytes per chunk.
