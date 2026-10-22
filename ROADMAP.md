# Roadmap

## V1 (current)

Local, single-user vault: encrypted storage, CLI, loopback dashboard, dotenv import/export.
See the [README](README.md).

## V2 (planned, not implemented)

- Hosted multi-user deployments.
- Account authentication and MFA.
- Team workspaces and role-based permissions.
- Secure sharing of projects and environments.
- Cloud sync between devices.
- Service accounts and scoped access tokens.
- CI/CD integrations.
- Advanced audit history.
- OS keychain integration for unlocking.
- Recovery-key workflows.
- External security review and further hardening.

Accounts, teams and terminal sharing are designed in [docs/v2-design.md](docs/v2-design.md).
Implemented so far (unreviewed): `ven server`, GitHub login, end-to-end encrypted hosted
projects, invites with expiry, approvals for protected environments, key rotation, read-only
service tokens and an audit log. Not yet: Google login, dashboard pages for teams, OS keychain.

Nothing in V2 is promised on a timeline; priorities will follow user feedback.
