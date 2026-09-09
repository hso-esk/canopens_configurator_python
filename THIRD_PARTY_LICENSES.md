# Third-Party Licenses

This project optionally integrates third-party libraries as external dependencies.
None of these libraries are bundled in this repository by default.
Each library is subject to its own license terms, independent of this project's
BSD 3-Clause license.

---

## wolfSSL

| Field       | Value |
|---|---|
| **Version** | 5.x (or as initialized via submodule) |
| **Website** | https://www.wolfssl.com |
| **Repository** | https://github.com/wolfSSL/wolfssl |
| **License** | GPLv3 (open source) OR Commercial |
| **License text** | https://www.wolfssl.com/license/ |
| **Used as** | Optional TLS backend (default build option) |
| **Included in repo** | ❌ No — optional git submodule, not initialized by default |

### License implications

wolfSSL is licensed under the **GNU General Public License v3.0 (GPLv3)**.

If you build this project with wolfSSL and distribute the resulting binary:
- Your binary must comply with the terms of GPLv3, including making
  source code available to recipients.
- Alternatively, you must obtain a **commercial license** from wolfSSL, Inc.
  See: https://www.wolfssl.com/license/

To initialize wolfSSL submodule:
```bash
git submodule update --init external/wolfssl