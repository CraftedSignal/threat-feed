---
title: Remote Code Execution in Craft CMS via HMAC Signature Misuse
slug: 2026-09-craft-cms-rce
description: Craft CMS versions 4.8.0 through 4.18.5 and 5.0.0 through 5.10.12 contain a critical vulnerability allowing authenticated users to achieve remote code execution by injecting malicious payloads into improperly validated redirect parameters.
date: "2026-09-16T23:53:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (4.8.0-4.18.5, 5.0.0-5.10.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated, non-administrator user (Control Panel access is not required) can set the cookie via the license-shun endpoint and transplant the signed envelope into the redirect parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: on a successful login, Craft validates the signature and renders the authenticated bytes as an unsandboxed Twig template, where Twig's map filter accepts a string callback and allows PHP system() to execute arbitrary operating-system commands
    confidence_band: high
cves:
  - id: CVE-2026-92592
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92592
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Craft CMS installations to 4.18.6 or 5.10.13
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in 4.18.6 and 5.10.13.
  mitigation_plan:
    - priority: immediate
      action: Enable mandatory MFA for all Craft CMS users
      owner: IT Operations
      addresses: CVE-2026-92592
      evidence: Exploitation requires an account using password authentication without active 2FA
---

Craft CMS versions 4.8.0 through 4.18.5 and 5.0.0 through 5.10.12 are susceptible to a remote code execution vulnerability identified as CVE-2026-92592. The issue stems from the application using the same securityKey to sign both internal license-shun cookies and redirect parameters without binding the HMAC signature to a specific purpose. 

An authenticated user, even without Control Panel administrative privileges, can manipulate the license-shun cookie and transplant the resulting signed data into a redirect parameter. When the user logs in, Craft CMS validates the signature and subsequently renders the attacker-controlled bytes as an unsandboxed Twig template. By leveraging Twig's map filter, the attacker can invoke PHP's system() function to execute arbitrary commands on the underlying host as the web-server user. Exploitation requires an authenticated account without active 2FA. The vendor has addressed this in Craft CMS versions 4.18.6 and 5.10.13.

## Attack Chain

1. Attacker authenticates to the target Craft CMS instance using standard credentials (2FA must be disabled).
2. Attacker interacts with the license-shun endpoint to set a malicious, attacker-controlled cookie.
3. Attacker extracts the signed signature from the license-shun cookie value.
4. Attacker crafts a redirect parameter containing an embedded Twig template payload utilizing the map filter and PHP system() function.
5. Attacker replaces the signature of the redirect parameter with the one harvested from the license-shun cookie.
6. Attacker triggers a login or redirect flow that processes the malicious parameter.
7. Craft CMS validates the HMAC signature, treats the parameter as trusted, and renders the content via the Twig engine.
8. Twig engine executes the PHP system() function, resulting in arbitrary code execution on the server.

## Impact

Successful exploitation results in full remote code execution under the privileges of the web-server process. This allows attackers to gain persistent access, exfiltrate sensitive site data, modify content, or pivot into the underlying server network. The vulnerability impacts all environments running the affected versions that allow non-admin authentication.

## Recommendation

1. Upgrade to Craft CMS 4.18.6 or 5.10.13 immediately to remediate CVE-2026-92592.
2. Enforce multi-factor authentication (MFA) for all user accounts to mitigate the prerequisite of successful authentication for this attack.
3. Audit webserver access logs for anomalous POST requests to the license-shun endpoint or unusual GET requests containing serialized data or Twig syntax within redirect parameters.
4. Restrict access to the Craft CMS control panel and related administrative endpoints to authorized IP ranges.
