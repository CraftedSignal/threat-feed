---
title: Authentication Bypass in Grav Clockwork Profiler
slug: 2026-10-grav-auth-bypass
description: Grav versions 2.0.22 through 2.1.6 are vulnerable to an authentication bypass in the Clockwork profiler that trusts loopback REMOTE_ADDR headers, potentially exposing system configuration and secrets.
date: "2026-10-12T18:35:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Grav (2.0.22-2.1.6)
cves:
  - id: CVE-2026-109325
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109325
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav instances to version 2.1.7 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109325 remediation requires update to 2.1.7
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Grav 2.1.7
      owner: IT Operations
      addresses: CVE-2026-109325
      evidence: NVD vulnerability details
---

Grav CMS versions 2.0.22 through 2.1.6 contain an authentication bypass vulnerability within the Clockwork profiler component. The vulnerability exists due to a logic flaw where the component implicitly trusts loopback addresses found in the REMOTE_ADDR header. Attackers positioned behind a same-host HTTP proxy can manipulate these headers to bypass authentication controls typically enforced on the profiler interface. Successful exploitation allows unauthorized access to sensitive application data, including system and plugin configuration files, sensitive secrets, database queries, and request metadata. This exposure presents a significant risk, as it provides an attacker with reconnaissance data that could facilitate further exploitation of the application or the underlying infrastructure. Organizations running affected versions are urged to upgrade to version 2.1.7 or later to remediate the vulnerability.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive application information, including configuration data, secrets, and internal request metadata. This exposure significantly lowers the barrier for subsequent attacks, potentially leading to full system compromise depending on the nature of the leaked secrets.

## Recommendation

* Upgrade Grav CMS to version 2.1.7 or later immediately to patch CVE-2026-109325.
* Audit access logs for unauthorized requests targeting the Clockwork profiler endpoints (e.g., /clockwork/app) that originate from non-loopback IPs but bypass authentication.
* Implement strict header validation at the web server or load balancer level to prevent REMOTE_ADDR header spoofing by untrusted clients.
