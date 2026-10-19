---
title: Default Credentials Vulnerability in FlyCms (CVE-2026-112296)
slug: 2026-10-flycms-default-creds
description: A default credentials vulnerability in FlyCms through commit edfdf724 allows unauthenticated attackers to gain administrative access using the flycms account and admin123 password.
date: "2026-10-19T16:08:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:flycms:flycms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - credential-abuse
vendors:
  - FlyCms
products:
  - FlyCms (<= edfdf724)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: FlyCms through commit edfdf724 contains a default credentials vulnerability that allows unauthenticated remote attackers to gain super administrator access via the flycms account with password admin123.
    confidence_band: high
cves:
  - id: CVE-2026-112296
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112296
rules:
  - title: Detect Potential Authentication Attempts to FlyCms with Default Credentials
    description: Detects HTTP POST requests to the FlyCms login endpoint that successfully authenticate, potentially indicating the use of default credentials.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and patch all FlyCms instances running commit edfdf724 or earlier.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-112296 identifies the vulnerability in FlyCms through commit edfdf724.
  mitigation_plan:
    - priority: immediate
      action: Disable the default flycms account or change its password immediately.
      owner: IT Operations
      addresses: CVE-2026-112296
      evidence: Vulnerability exploits default credentials for the flycms account.
---

FlyCms versions through commit edfdf724 contain a critical default credentials vulnerability. An unauthenticated remote attacker can exploit this flaw by leveraging the default username 'flycms' and password 'admin123'. By sending a POST request to the application's authentication endpoint and successfully solving the required image captcha, an attacker can authenticate as a super administrator. This grants the attacker full control over the application's content, user management, and system configuration. Given the ease of exploitation and the level of access granted, organizations running affected versions of FlyCms are at high risk of unauthorized site takeover.

## Impact

Successful exploitation results in full administrative control over the FlyCms instance. This allows attackers to modify site content, manipulate user accounts, and alter system configurations, potentially leading to persistent unauthorized access, data exfiltration, or further compromise of the underlying hosting environment.

## Recommendation

- Immediately audit all FlyCms instances to identify and update any installations running code versions at or prior to commit edfdf724.
- Implement a policy to change default vendor credentials upon initial deployment for all web-based content management systems.
- Monitor web server access logs for anomalous POST requests to /api/auth/login that originate from unexpected or external IP addresses.
- Restrict access to administrative login endpoints to trusted IP ranges or VPN-only access to prevent public exploitation attempts.
