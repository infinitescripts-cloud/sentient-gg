# Changelog

## 3.0.0 — Cloudflare platform expansion

- Added bulk license creation (up to 100 per request) with one-time key display.
- Added dashboard statistics API.
- Added project editing, build deletion, license editing, activation listing, and individual activation removal.
- Improved the minimizer to preserve long-bracket string contents and operator token boundaries.
- Expanded tests for long strings/comments and operator spacing.
- Hardened activation-limit enforcement against concurrent first-time activations.
- Added a GitHub Actions test workflow and a server-side Roblox license-validation example.
- Expanded deployment and API documentation.

This release is still an administrator-focused platform. It is not a complete multi-tenant SaaS product, a Luau compiler, or an advanced VM/anti-tamper protection engine.
