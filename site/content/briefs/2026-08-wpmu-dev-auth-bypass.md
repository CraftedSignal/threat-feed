---
title: Authentication Bypass in WPMU DEV Dashboard Plugin
slug: 2026-08-wpmu-dev-auth-bypass
description: An authentication bypass vulnerability in WPMU DEV Dashboard plugin versions 5.0.0 and earlier allows unauthenticated attackers to invoke privileged administrative actions via forged request signatures.
date: "2026-08-06T07:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WPMU DEV
products:
  - WPMU DEV Dashboard
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The remote handler is bound to the public init hook with no capability check.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to invoke privileged Hub actions... including logging in as an administrator via SSO.
    confidence_band: high
cves:
  - id: CVE-2026-15459
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15459
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade WPMU DEV Dashboard to version > 5.0.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15459
  mitigation_plan:
    - priority: immediate
      action: Connect sites to WPMU DEV Hub to prevent empty API key exploitation
      owner: IT Operations
      addresses: CVE-2026-15459
      evidence: Sites connected to a WPMU DEV account, which have a non-empty 64-character API key, are not affected.
---

The WPMU DEV Dashboard plugin for WordPress is vulnerable to an authentication bypass (CVE-2026-15459) affecting all versions up to and including 5.0.0. The vulnerability stems from how the plugin handles request signatures when a site has not been connected to the WPMU DEV Hub. In this default state, the site API key is empty, causing the `validate_hash()` function to accept trivially forgeable signatures. Furthermore, the removal of replay checks in `validate_nonce()` in version 5.0.0 and the absence of capability checks on the public `init` hook allow unauthenticated actors to execute sensitive administrative functions. This impact includes arbitrary plugin installation from remote URLs, leading to full remote code execution, as well as administrative account takeover via SSO. Sites with an active WPMU DEV account and a populated API key are not susceptible to this specific vector.

## Impact

Successful exploitation allows unauthenticated attackers to gain complete control over affected WordPress installations. Potential impacts include remote code execution through the installation of malicious plugins, unauthorized modification of site content (deletion of themes and plugins), unauthorized WordPress core upgrades, and full administrative access via SSO mechanisms. All WordPress sites running WPMU DEV Dashboard versions 5.0.0 or lower that remain disconnected from the WPMU DEV Hub are at risk.

## Recommendation

- Upgrade the WPMU DEV Dashboard plugin to the latest version beyond 5.0.0 immediately.
- If upgrading is not immediately possible, connect affected sites to the WPMU DEV Hub to populate the API key, thereby mitigating the forgeable signature condition.
- Review web access logs for anomalous `POST` requests to WordPress `init` hooks or plugins/dashboard endpoints originating from unexpected sources.
- Audit existing plugin and theme installations on WordPress environments to identify unauthorized or suspicious additions since the deployment of vulnerable versions.
