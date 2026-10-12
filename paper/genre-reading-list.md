# Section 2 literature: sources and verification status

Updated 28 September 2026. Every reference in `manuscript/refs.bib` for Section 2 has bibliographic fields (authors, title, venue, volume, year, DOI) verified against OpenAlex or Crossref metadata. Table 1 rows were written **from the abstract only**, which I read in full. Before submission, skim each full paper once so that the description in the table is fair to its authors; the abstracts are accurate summaries of what the papers claim, but a full read may turn up a reduction or a key-transport description the abstract omits.

## Table 1: twelve rows, all abstract-verified

| Cite key | Group | Paper | DOI |
|---|---|---|---|
| `bhogal2018cataes` | cipher retained | Bhogal, Li, Gale, Chen. Medical Image Encryption using Chaotic Map Improved AES. IJITCS 10(8), 2018 | 10.5815/ijitcs.2018.08.01 |
| `arab2019chaosaes` | cipher retained | Arab, Rostami, Ghavami. An image encryption method based on chaos system and AES algorithm. J. Supercomputing 75(10):6663–6682, 2019 | 10.1007/s11227-019-02878-7 |
| `hashim2021hybridaes` | cipher retained | Hashim, Jabbar, Hassan. Medical Image Encryption Based on Hybrid AES with Chaotic Map. J. Phys. Conf. Ser. 1973, 2021 | 10.1088/1742-6596/1973/1/012037 |
| `bayesh2025chaoticaes` | cipher retained | Bayesh, Das, Ahadullah. Dual-Layer Image Encryption Using Chaotic AES with Dynamic S-Boxes and Steganographic QR Codes. arXiv 2506.13895, 2025 | – |
| `ibrahim2020dynamicsbox` | chaos is the cipher | Ibrahim et al. Framework for Efficient Medical Image Encryption Using Dynamic S-Boxes and Chaotic Maps. IEEE Access 8, 2020 | 10.1109/ACCESS.2020.3020746 |
| `almaadeed2021lorenzsbox` | chaos is the cipher | Al-Maadeed, Hussain, Anees, Mustafa. Image encryption based on chaotic Lorenz system and primitive polynomial S-boxes. MTA 80, 2021 | 10.1007/s11042-021-10695-5 |
| `hasan2021lightweight` | chaos is the cipher | Hasan et al. Lightweight Encryption Technique to Enhance Medical Image Security on IoMT. IEEE Access 9, 2021 | 10.1109/ACCESS.2021.3061710 |
| `daoui2022meixner` | chaos is the cipher | Daoui et al. Biomedical Multimedia Encryption by Fractional-Order Meixner Polynomials Map. IEEE Access 10, 2022 | 10.1109/ACCESS.2022.3203067 |
| `inam2024arnold` | chaos is the cipher | Inam, Kanwal, Firdous, Hajjej. Blockchain based medical image encryption using Arnold's cat map. Sci. Rep. 14, 2024 | 10.1038/s41598-024-56364-z |
| `jain2024mmcbie` | chaos is the cipher | Jain et al. A Lightweight Multi-Chaos-Based Image Encryption Scheme for IoT Networks. IEEE Access 12, 2024 | 10.1109/ACCESS.2024.3377665 |
| `asiri2025bitplane` | chaos is the cipher | Asiri et al. Enhancing medical image privacy in IoT with bit-plane level encryption using chaotic map. Front. Comput. Neurosci. 19, 2025 | 10.3389/fncom.2025.1591972 |
| `ravichandran2025shuffling` | chaos is the cipher | Ravichandran et al. Efficient medical data encryption using selective shuffling and inter-intra pixel diffusion. Sci. Rep. 15, 2025 | 10.1038/s41598-025-85539-5 |

## The other meaning of "hybrid" (key-encapsulation composition), cited in the closing paragraph

`elhoseny2018iot` (IEEE Access 6, 546 citations), `zhang2019paes` (IJDMS 11(1)), `popoola2024smarthome` (Internet of Things 27, uses AES-EAX), `selvi2025symeccipher` (Sci. Rep. 15), `chowdhary2020hybrid` (Sensors 20(18)).

## Requirements, cryptanalysis and reviews of chaos-based schemes

`alvarez2006requirements` (IJBC 16(8), 2,100+ citations, the standard reference), `hua2019cosine` (Inf. Sci. 480), `feng2021cryptanalysis` (IEEE Access 9), `zhang2023chaosreview` (Mathematics 11(11)), `ahmed2023mireview` (Computers 12(8)).

## Wider EHR-security literature (§2.4)

`oh2021ehealthsurvey` (IJERPH 18(18)), `keshta2021ehr` (Egyptian Informatics J. 22(2)), `li2013abe` (IEEE TPDS 24(1), ~1,200 citations), `nguyen2019blockchainehr` (IEEE Access 7), `shi2020blockchainehr` (Computers & Security 97, the target journal), `mandel2016smartfhir` (JAMIA 23(5)).

## Removed from the manuscript

Three references were in an earlier draft on the strength of title and metadata only and have been removed because their abstracts could not be accessed: Ahmed et al. 2023 (MTA, 10.1007/s11042-023-15925-6), Kiah et al. 2013 (J. Med. Syst., 10.1007/s10916-013-9971-2), Zhang et al. 2026 (Nonlinear Dynamics, 10.1007/s11071-025-11994-4). Also not accessible: Leelavathi et al. 2025 (SN CS, 10.1007/s42979-025-03961-y), Inam et al. 2025 (Cluster Computing, 10.1007/s10586-025-05355-4). If you have institutional access, any of these could be added as a thirteenth or fourteenth row; none is needed.

## Details still worth checking with the full text

- Page numbers for the IEEE Access entries (OpenAlex did not carry them); the DOI resolves regardless.
- `bhogal2018cataes` volume: the DOI's year and issue are certain; confirm the volume is 10.
- `hua2019cosine`: online 2018, volume 480 is 2019; cited as 2019.
- `li2013abe` and `keshta2021ehr`: online a year before the printed volume; cited by printed volume.
