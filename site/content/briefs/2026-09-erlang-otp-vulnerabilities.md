---
title: Vulnerabilities in Erlang/OTP
slug: 2026-09-erlang-otp-vulnerabilities
description: Multiple security vulnerabilities identified in Erlang/OTP across various version branches require immediate patching to mitigate potential risks.
date: "2026-09-22T19:47:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:erlang:otp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - erlang
  - patch-management
vendors:
  - Erlang
products:
  - OTP (17.0 < 27.3.4.18)
  - OTP (22.2 < 27.3.4.18, 28.5.0.7, 29.1.1)
  - OTP (4.1.1 < 5.2.11.13, 5.5.2.6, 6.0.6)
  - OTP (9.5 < 11.2.12.13, 11.6.0.6, 11.7.7)
cves:
  - id: CVE-2026-65634
  - id: CVE-2026-89422
references:
  - https://cyber.gc.ca/en/alerts-advisories/erlang-security-advisory-av26-948
  - https://cna.erlef.org/cves/CVE-2026-65634.html
  - https://cna.erlef.org/cves/CVE-2026-89422.html
  - https://github.com/erlang/otp/security/advisories/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Erlang/OTP environments to versions 27.3.4.18, 28.5.0.7, 29.1.1, 5.2.11.13, 5.5.2.6, 6.0.6, 11.2.12.13, 11.6.0.6, or 11.7.7 based on the specific branch in use.
      owner: IT Operations
      addresses: CVE-2026-65634, CVE-2026-89422
      evidence: Source provides specific version branches and upgrade targets
---

The Cyber Centre has released an advisory regarding multiple vulnerabilities affecting the Erlang Open Telecom Platform (OTP). The identified vulnerabilities, tracked as CVE-2026-65634 and CVE-2026-89422, impact several versions of the OTP framework. Affected branches include multiple release paths, with specific patch requirements documented for versions including 17.0, 22.2, 4.1.1, and 9.5. Given the foundational nature of Erlang/OTP in distributed systems and telecommunications, these vulnerabilities could potentially lead to service disruption or unauthorized system access if exploited. Organizations running Erlang environments should review their current build versions against the upstream security advisories provided by the Erlang/OTP project and apply the recommended version updates immediately.

## Impact

Successful exploitation of these vulnerabilities could result in instability or compromise of systems relying on the Erlang/OTP runtime. While the specific impact of the identified CVEs is not detailed in the advisory, vulnerabilities in this runtime environment frequently allow for arbitrary code execution or significant denial-of-service conditions, affecting the integrity and availability of production applications.

## Recommendation

- Upgrade Erlang/OTP installations to the secure versions as specified in the vendor security advisory.
- Review the official Erlang/OTP GitHub security advisories for specific release notes regarding CVE-2026-65634 and CVE-2026-89422.
- Audit infrastructure to identify all instances of Erlang/OTP to ensure comprehensive patching across the environment.
