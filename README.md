> ## ✅ TESTED AND TRANSFERRED
>
> This repository has been consolidated into the canonical account. All code, fixes, tests, and
> documentation now live at:
>
> **→ https://github.com/echoomegaprime/echo-booking**
>
> - Destination commit: `3da10ee044fdd380dd77c931d0292e2f2f1ace1e`
> - Cert Forge certificate: `cert_6b40011f9604c973e23816248d9815607b72734c` — `PRODUCTION_READY`
>   (evidence Merkle root `6c972a9ae24e1b5319e910b2f1f693f29894751583b9362da5d2052291ca21fd`,
>   verify at https://cert-api.echosforge.com/v1/certifications/cert_6b40011f9604c973e23816248d9815607b72734c/verdict)
> - GitHub App Suite conformance: manual receipt at
>   [`.echo/repo-health.md`](https://github.com/echoomegaprime/echo-booking/blob/main/.echo/repo-health.md)
>   in the destination repo (GitHub App Suite auto-posting affected by build #29466 on this
>   account; this is the documented workaround)
> - Transfer date: 2026-08-12
>
> **Security note**: during transfer, one real fix was made — every `GET` route was previously
> readable by anyone who had a tenant ID (no authentication required for reads, only writes),
> including customer PII, appointment detail, and revenue analytics. See
> [SECURITY.md in the destination repo](https://github.com/echoomegaprime/echo-booking/blob/main/SECURITY.md).
>
> This legacy repository is preserved for provenance and is not actively maintained. Do not
> open issues or PRs here — use the destination repository above.

---

# echo-booking

AI-powered appointment scheduling with Stripe payments. See the destination repository linked
above for current documentation, tests, and security fixes.
