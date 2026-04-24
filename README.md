# kek-dek-encryption


base_kek (from .env) ──────┐
                            │
                           HMAC
                            │
version string ("v1") ──────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ 32-byte KEK   │  ← derived KEK
                    └───────────────┘
