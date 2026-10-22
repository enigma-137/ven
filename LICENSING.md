# Licensing — decision pending

VEN is intended to be open source, but **no license has been granted yet**. Until the owner
adds a `LICENSE` file, the code is "all rights reserved" by default, so please finalize this
before publishing or accepting outside contributions.

## Recommendation: Apache License 2.0

- Permissive, so individuals and companies can use VEN freely.
- Includes an explicit patent grant and patent-retaliation clause, which MIT lacks.
- Widely understood; compatible with all current dependencies (MIT, BSD-3-Clause, Apache-2.0).

Alternatives the owner may prefer:

| License | When to choose it |
| --- | --- |
| MIT | Simplest permissive license; no patent language. |
| MPL-2.0 | Modifications to VEN's own files must stay open; can be combined with closed code. |
| AGPL-3.0 | Hosted (V2) forks offered over a network must publish their changes. |

## To finalize

1. Choose a license.
2. Add the full, unmodified license text as `LICENSE` in the repository root
   (for Apache-2.0: <https://www.apache.org/licenses/LICENSE-2.0.txt>).
3. Set `"license"` in `web/package.json` to the SPDX identifier (for example `Apache-2.0`).
4. Update this file to state the chosen license (or delete it and mention the license in the README).

## Third-party dependencies

Go: `spf13/cobra` (Apache-2.0), `modernc.org/sqlite` (BSD-3-Clause), `golang.org/x/crypto`,
`golang.org/x/term`, `golang.org/x/sys` (BSD-3-Clause). Frontend: React, TanStack, Radix UI,
lucide-react, Tailwind CSS, clsx, tailwind-merge, Vite (MIT; lucide-react is ISC). Their notices
must be preserved in binary distributions; verify against each package's own license file
before a release.
