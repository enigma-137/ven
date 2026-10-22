# Security policy

VEN stores credentials, so security reports are very welcome. VEN V1 has **not** been
externally reviewed; see [docs/security.md](docs/security.md) for the threat model and known
limitations before reporting something listed there as out of scope.

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue, pull request or
discussion for a suspected vulnerability.

Use GitHub's private vulnerability reporting for this repository: open the repository's
**Security** tab and choose **Report a vulnerability**. (Maintainers: enable it under
*Settings → Code security → Private vulnerability reporting*. If you add another private
contact channel, list it here.)

Please include:

- the VEN version (`ven version`) and operating system
- what an attacker needs (local access, a malicious web page, a copied vault file, …)
- steps to reproduce, ideally with a throwaway vault and dummy values
- the impact you observed

**Never include real credentials, real vault files or real master passwords in a report.**

## What to expect

This is a volunteer-maintained project without a guaranteed response time. Maintainers will
aim to acknowledge reports, keep you informed while a fix is prepared, and credit you in the
release notes if you wish. Please allow time for a fix before any public disclosure.

## Supported versions

Only the latest release receives security fixes during V1.
