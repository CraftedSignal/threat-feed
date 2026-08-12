---
title: Nagios Core and XI CSRF Protection Bypass
slug: 2026-08-nagios-csrf-bypass
description: Nagios Core and XI contain a CSRF protection bypass vulnerability (CVE-2026-48551) that allows unauthenticated attackers to execute commands as an authorized user via manipulated double-submit cookies.
date: "2026-08-12T18:50:49Z"
lastmod: "2026-08-12T18:50:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - monitoring
vendors:
  - Nagios
products:
  - Nagios Core
  - Nagios XI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: An attacker can supply matching cookie and request parameter values to bypass CSRF protection, enabling unauthenticated attackers to run commands as authorized users via malicious links.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated attacker with NRDP access can inject OS commands through the macro value.
    confidence_band: high
cves:
  - id: CVE-2026-48551
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48551
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48553
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Nagios Core and Nagios XI to specified versions
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-48551 advisory
updates:
  - at: "2026-08-12T18:50:57Z"
    level: L2
    summary: added coverage for Nagios Core +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48553
---

Nagios Core (versions prior to 4.5.14) and Nagios XI (versions prior to 2026R1.7) are susceptible to a cross-site request forgery (CSRF) protection bypass identified as CVE-2026-48551. The vulnerability stems from an insecure implementation of double-submit cookie validation. By supplying matching cookie and request parameter values, an attacker can circumvent the application's CSRF defenses. This allows an unauthenticated remote attacker to trick an authenticated user into unknowingly executing malicious actions or commands within the web interface, essentially hijacking the user's session context for unauthorized tasks. This issue is significant for security and infrastructure monitoring platforms, as successful exploitation could lead to full system control or configuration changes by unauthorized parties.

## Impact

The vulnerability poses a high risk to organizations relying on Nagios for infrastructure monitoring, as it permits unauthenticated remote attackers to perform actions with the privileges of an active, authenticated administrator session. Potential damage includes unauthorized modification of monitoring configurations, deletion of critical alerts, or the execution of arbitrary system commands through the application's administrative interface.

## Recommendation

Prioritized actions for administrators and security teams:

- Upgrade Nagios Core to version 4.5.14 or later immediately.
- Upgrade Nagios XI to version 2026R1.7 or later immediately.
- Restrict network access to Nagios administrative interfaces using IP whitelisting or VPNs to limit the exposure of the vulnerable web endpoints until patches are applied.
- Audit web server access logs for requests containing suspicious or inconsistent cookie-to-parameter values that suggest an attempt to bypass standard CSRF protections.
