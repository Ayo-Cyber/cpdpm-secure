# Table 1 reading list

Seven references are in the manuscript. Bibliographic fields (authors, title, venue, year, DOI) were verified against publisher or Semantic Scholar metadata on 23 September 2026. The table cells were filled **from abstracts only** for the first four; the last three need the full text before their cells are final, and every row deserves a skim of the full paper before submission so that the description is fair to the authors.

## Characterised from the abstract (confirm against full text)

| Cite key | Paper | DOI | What the abstract says |
|---|---|---|---|
| `hashim2021hybridaes` | Hashim, Jabbar, Hassan. Medical Image Encryption Based on Hybrid AES with Chaotic Map. J. Phys.: Conf. Ser. 1973, 2021 | 10.1088/1742-6596/1973/1/012037 | Quadratic map as preprocessing to "nullify the relationship between pixels", then AES. Claim: "broad enough to avoid brute-force attacks". Evidence: statistical, key sensitivity. Key handling: not stated. |
| `bayesh2025chaoticaes` | Bayesh, Das, Ahadullah. A Dual-Layer Image Encryption Framework Using Chaotic AES with Dynamic S-Boxes and Steganographic QR Codes. arXiv 2506.13895, 2025 | – | Logistic map drives ShiftRows; Henon map generates S-boxes and key expansion inside AES-128; post-encryption XOR diffusion. Evidence: entropy 7.997, NPCR >99.6%, UACI. Keys: static + AES-encrypted session key embedded in a QR code by LSB steganography, carried with the data. |
| `asiri2025bitplane` | Asiri et al. Enhancing medical image privacy in IoT with bit-plane level encryption using chaotic map. Front. Comput. Neurosci. 19, 2025 | 10.3389/fncom.2025.1591972 | Chen chaotic map shuffles and diffuses bit planes; no standard cipher. Claim: "high degree of resilience to attacks". Evidence: correlation, histogram, key space (10^90)^8, entropy > 7.98, NPCR/UACI. Key: initial conditions from SHA of the plaintext. |
| `ravichandran2025shuffling` | Ravichandran et al. An efficient medical data encryption scheme using selective shuffling and inter-intra pixel diffusion. Sci. Rep. 15, 2025 | 10.1038/s41598-025-85539-5 | Combined Chaotic System sequences for row/column shuffling, intra- and inter-pixel diffusion; no standard cipher stated. Claim: resists chosen-plaintext and chosen-ciphertext attacks. Seeds from hash of intermediate images. |

## Bibliographic record only (read before Friday, fill the three `\todo{confirm}` cells)

| Cite key | Paper | DOI |
|---|---|---|
| `ahmed2023hyperchaotic` | Ahmed, Elkamchouchi, Elfahar, El-Shafai, Mohamed. A hybrid medical image cryptosystem based on 4D-hyperchaotic S-boxes and logistic maps. Multimedia Tools and Applications 83:8837–8865, 2023 | 10.1007/s11042-023-15925-6 |
| `kiah2013aeshybrid` | Kiah, Nabi, Zaidan, Zaidan. An Enhanced Security Solution for Electronic Medical Records Based on AES Hybrid Technique with SOAP/XML and SHA-1. J. Med. Syst. 37(5), 2013 | 10.1007/s10916-013-9971-2 |
| `zhang2026finitefield` | Zhang, Lin, Chen, Sun. A hybrid cryptosystem for medical image security: integrating finite fields with conservative hyperchaos. Nonlinear Dynamics 114, 2026 | 10.1007/s11071-025-11994-4 |

For each: transform stage and its order relative to any standard cipher; the security claim as stated; the evidence offered; how the transform key reaches the receiver (secret, shared, transmitted, derived from plaintext, fixed).

## Candidates found but not included

- Lee, Chang, Kung. Blockchain-Based Healthcare Information Preservation Using Extended Chaotic Maps for HIPAA. Applied Sciences 11(22), 2021. Uses chaotic maps for key negotiation, not as a data transform; out of scope for Table 1.
- "A Robust Chaos-Based Technique for Medical Image Encryption", IEEE Access, ieeexplore.ieee.org/document/9663264. Chaos-only; would strengthen the IEEE Access representation if you can access it.
- Leelavathi, Priyadarshini, Puttegowda. Securing Telehealth EHRs with Adaptive Chaotic Encryption. SN Computer Science 6, 2025. 10.1007/s42979-025-03961-y. Abstract not accessible; likely relevant.
- Inam, Kanwal, Nawaz, Alkhalifa. Enhanced medical image security: a chaotic map and Laplace transform-based scheme. Cluster Computing 28, 2025. 10.1007/s10586-025-05355-4. Abstract not accessible.

Twelve rows would be stronger than seven. The last two candidates and one or two IEEE Access papers found through your institutional access would get there.
