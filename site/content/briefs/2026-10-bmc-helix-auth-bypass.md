---
title: Authentication Bypass in BMC Helix Network Management
slug: 2026-10-bmc-helix-auth-bypass
description: BMC Helix Network Management on-prem versions prior to 26.3.01 allow unauthenticated attackers to bypass SAML authentication and gain administrator access.
date: "2026-10-15T22:41:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:bmc:helix_network_management:*:*:*:*:*:*:*:*
vendors:
  - BMC
products:
  - Helix Network Management (< 26.3.01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker can log in as the local administrator with any password when SAML single sign-on is configured.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attacker obtains a SuperAdmin session, allowing them to modify device credentials and run device commands.
    confidence_band: high
cves:
  - id: CVE-2026-111283
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111283
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade BMC Helix Network Management on-prem to version 26.3.01 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version 26.3.01 or later
  mitigation_plan:
    - priority: immediate
      action: Disable SAML SSO or restrict web interface access to trusted networks
      owner: IT Operations
      addresses: CVE-2026-111283
      evidence: NVD vulnerability details suggest authentication bypass occurs when SAML SSO is configured
---

BMC Helix Network Management on-prem instances running versions prior to 26.3.01 are vulnerable to an authentication bypass when SAML single sign-on is enabled. The vulnerability exists due to improper validation of authentication credentials during the SAML login flow. An unauthenticated attacker can supply the known administrator username and any arbitrary password via the web login page to bypass standard authentication mechanisms. Successful exploitation grants the attacker full SuperAdmin privileges, allowing for unauthorized execution of device commands, modification of stored device credentials, and alteration of audit records within the environment. This vulnerability poses a significant risk to organizational infrastructure, as it enables total control over the network management platform.

## Impact

Successful exploitation allows unauthenticated actors to gain full administrative control over the BMC Helix Network Management instance. This grants the attacker the ability to modify device credentials, execute arbitrary commands on managed network infrastructure, and tamper with audit logs to conceal malicious activity. The vulnerability impacts organizations using on-premise deployments of BMC Helix Network Management with SAML SSO configurations.

## Recommendation

- Upgrade BMC Helix Network Management on-prem to version 26.3.01 or later immediately.
- Until patching is complete, disable SAML SSO for the affected application or restrict access to the web login interface to trusted management networks using firewall rules.
- Review audit logs for unauthorized login attempts or anomalous administrative sessions occurring from unknown IP addresses, specifically looking for attempts to authenticate as the local administrator account.
