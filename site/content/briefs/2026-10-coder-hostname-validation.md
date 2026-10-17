---
title: Improper Hostname Validation in Coder Workspace Proxy
slug: 2026-10-coder-hostname-validation
description: Coder versions prior to 2.29.20, 2.33.12, 2.34.8, and 2.35.4 are vulnerable to an improper hostname validation flaw, allowing attackers to intercept workspace API keys via crafted redirect links.
date: "2026-10-17T20:54:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coder:coder:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-111927
vendors:
  - Coder
products:
  - Coder (< 2.29.20, >= 2.33.0 < 2.33.12, >= 2.34.0 < 2.34.8, >= 2.35.0 < 2.35.4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers owning such a domain can lure an authenticated victim to a crafted /api/v2/applications/auth-redirect link, capture the redirected application_connect API key.
    confidence_band: high
cves:
  - id: CVE-2026-111927
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111927
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Coder to fixed versions 2.29.20, 2.33.12, 2.34.8, or 2.35.4
      owner: IT Operations
      due: 24h
      evidence: Source provides fixed versions to remediate CVE-2026-111927
  mitigation_plan:
    - priority: immediate
      action: Upgrade Coder to 2.29.20 or later
      owner: IT Operations
      addresses: CVE-2026-111927
      evidence: NVD documentation
---

Coder versions prior to 2.29.20, 2.33.12, 2.34.8, and 2.35.4 contain a critical vulnerability in the GetWorkspaceProxyByHostname function. The application uses a SIMILAR TO pattern that performs an insecure prefix match for hostname validation. This flaw allows an attacker to register or control a malicious domain that is a string prefix of a legitimate workspace-proxy access URL. By luring an authenticated victim into clicking a specially crafted link pointing to /api/v2/applications/auth-redirect, an attacker can capture sensitive application_connect API keys. These captured keys can then be replayed to gain unauthorized access to the victim's workspace applications, potentially resulting in full workspace compromise and lateral movement within the development environment.

## Impact

Successful exploitation allows for the theft of workspace-specific API keys. An attacker with these credentials can impersonate the victim, gain unauthorized access to workspace applications, and potentially exfiltrate sensitive source code, development environment secrets, or interact with cloud resources configured within the workspace.

## Recommendation

1. Upgrade all Coder installations to the patched versions: 2.29.20, 2.33.12, 2.34.8, or 2.35.4 or later.
2. Implement strict domain allowlisting for workspace-proxy access URLs to mitigate potential prefix collision attacks.
3. Audit existing Coder API keys for unauthorized usage patterns if the environment was exposed during the period preceding the patch.
