# CSA5111-CNS Assignment 4 – Part II implementation

Run everything: `pip install cryptography` then `python run_all.py` (needs `openssl` on PATH for Tasks 2 and 4).
Each script prints predictions before results; captured runs are in `outputs/`.

| Task | File | What it does |
|---|---|---|
| 1 PGP-style engine | `pgpmail.py`, `task1_run.py` | sign → compress → AES-256-GCM → RSA-OAEP per recipient; labelled hex view; 1/5-recipient and 10× message runs; tamper/boundary tests |
| 2 S/MIME vs PGP | `pki.py`, `task2_run.py` | root→intermediate→users with OpenSSL CMS; 6 failure cases (expired, rogue CA, email mismatch, CRL revocation, tampered body, missing intermediate); web-of-trust failure; comparison |
| 3 IPsec ESP | `task3_esp.py` | tunnel-mode ESP (AES-GCM) with W=32 anti-replay, window-edge tests, tamper/unknown SPI/rekey, coverage table, NAT experiment (ESP vs AH) |
| 4 HTTPS | `task4_https.py` | TLS 1.3 service with mTLS and security headers, `openssl s_client -msg` handshake, predict-then-run table, downgrade experiment |
| 5 SPF/DKIM/DMARC | `task5_mailauth.py` | own checkers over a simulated DNS zone; six constructed messages with evidence traces and outcome table |
| 6 Mass mailing | `task6_bulk.py` | key-state model, X25519 wrap engine, hand-derived validation, growth table to n=10,000 |

Notes and assumptions
- All keys and certificates are generated at run time (test data only); no private keys are in the source.
- Task 3 is a simulation (no strongSwan); Task 4 uses Python's `ssl` with OpenSSL. No packet capture file is produced; the handshake is shown through `s_client -msg`.
- Written answers (interpretations, 2.4, 4.5, 6.6, 6.7) are printed by the scripts alongside the evidence.
- The earlier `../assignment4.c` implements the Part I pseudocode (replay window, S/MIME check, web of trust, spam score).
