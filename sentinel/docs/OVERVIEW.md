# Sentinel Overview

## Architecture
- **Tokenizer:** lowercases text; splits on non-alnum and whitespace.
- **Model:** unigram and bigram counts with add-1 smoothing.
- **Scoring:** negative log-likelihood; robust Z via median/MAD.
- **Outputs:** CLI, HTML report, real-time streaming.

## Threat Model & Risks
- Reads logs (R/O). No network egress by default.
- Model poisoning possible if trained on compromised periods — curate training windows.
- High-entropy tokens (UUIDs, request IDs) may inflate scores; consider `--min-count` and per-source models.

## Security Guidance
- Run as least-privileged user with read-only access to logs.
- Separate models by source (auth, web, dns).
- Periodic retraining with vetted data; track model drift in VCS.

## Roadmap
- Trigram/Kneser–Ney
- Simple webhook notifier
- Backtesting for threshold tuning
