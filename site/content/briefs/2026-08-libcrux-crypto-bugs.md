---
title: Cryptographic Implementation Vulnerabilities in libcrux
slug: 2026-08-libcrux-crypto-bugs
description: Multiple cryptographic implementation vulnerabilities in the libcrux library (CVE-2026-76234) allow for denial of service and improper cryptographic validation.
date: "2026-08-19T14:35:31Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - cryptographic-flaw
  - library-vulnerability
vendors:
  - celabshq
products:
  - libcrux-ecdh
  - libcrux-ed25519
  - libcrux-psq
cves:
  - id: CVE-2026-76234
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76234
  - https://github.com/celabshq/libcrux/security/advisories/GHSA-435g-fcv3-8j26
action_plan:
  priority: elevated
  owners:
    - Development Team
    - AppSec
  immediate_actions:
    - action: Update libcrux dependencies in projects to version >= 0.0.6 for ecdh/ed25519 and >= 0.0.7 for psq.
      owner: Development Team
      due: 72h
      evidence: Vendor patch availability in security advisory.
---

The libcrux cryptographic library, specifically components libcrux-ecdh, libcrux-ed25519, and libcrux-psq, contains implementation bugs that affect cryptographic integrity and system stability. Research indicates that libcrux-ecdh failed to properly validate secret key length and clamping for X25519 keys, leading to potential validation errors. libcrux-ed25519 was found to perform redundant clamping during key generation, while libcrux-psq triggered a panic condition instead of propagating an AEADError when encountering errors. These vulnerabilities are tracked under CVE-2026-76234 and are fixed in libcrux-ecdh version 0.0.6, libcrux-ed25519 version 0.0.6, and libcrux-psq version 0.0.7. The primary impact is the potential for service disruption through forced application panics and non-standard cryptographic behavior that could be triggered by malicious input.

## Impact

Successful exploitation or triggering of these vulnerabilities can lead to service denial via application crashes (panics). Furthermore, the improper validation of cryptographic parameters may compromise the intended security properties of X25519 key exchanges or Ed25519 operations in applications that rely on these library versions.

## Recommendation

Prioritized actions for development and security engineering teams:
- Inventory all internal applications and services utilizing the libcrux Rust crate.
- Upgrade libcrux-ecdh and libcrux-ed25519 to version 0.0.6 or higher.
- Upgrade libcrux-psq to version 0.0.7 or higher.
- Monitor for application crashes or panic-related logs in services consuming these specific cryptographic primitives, particularly those exposed to unauthenticated network input.
