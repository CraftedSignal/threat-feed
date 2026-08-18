---
title: Critical Authentication Bypass in Red Hat Build of Keycloak
slug: 2026-08-keycloak-auth-bypass
description: A critical vulnerability (CVE-2026-18963) in the keycloak-services component allows unauthenticated attackers to hijack user accounts by bypassing password reset verification requirements.
date: "2026-08-18T18:55:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - identity-management
  - cve-2026-18963
vendors:
  - Red Hat
products:
  - Red Hat Build of Keycloak
  - Red Hat JBoss Enterprise Application Platform Expansion Pack
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The issue allows an unauthenticated attacker to force the password reset process for any user.
    confidence_band: high
cves:
  - id: CVE-2026-18963
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18963
  - https://access.redhat.com/security/cve/CVE-2026-18963
  - https://bugzilla.redhat.com/show_bug.cgi?id=2511595
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Red Hat Build of Keycloak and JBoss EAP Expansion Pack using official Red Hat security updates.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18963 requires urgent patching to mitigate critical authentication bypass risk.
---

CVE-2026-18963 is a critical vulnerability affecting the keycloak-services component within Red Hat Build of Keycloak and the Red Hat JBoss Enterprise Application Platform (EAP) Expansion Pack. This vulnerability stems from a flaw in the identity and access management engine's reset-credentials flow. An unauthenticated attacker can exploit this weakness to initiate a password reset process for any user in the system. Crucially, the exploit circumvents the requirement for an email-based verification link, allowing the attacker to directly set a new password for the target account. Given its nature as an identity provider, successful exploitation grants the attacker full unauthorized access to target accounts, potentially leading to widespread lateral movement or data exfiltration within an organization's authentication infrastructure.

## Attack Chain

1. Attacker identifies a target Keycloak instance exposed to the network.
2. Attacker crafts a specific HTTP request targeting the password reset endpoint provided by keycloak-services.
3. Attacker submits the targeted username or identifier through the vulnerable reset-credentials flow.
4. The Keycloak application fails to validate the necessity of the email verification step due to the logic flaw in the services component.
5. The application accepts the request and proceeds to the credential update stage.
6. Attacker provides the desired new password for the compromised user account.
7. Keycloak processes the update, overwriting the legitimate user's credentials with the attacker-controlled password.
8. Attacker authenticates as the victim user, achieving full account takeover and subsequent persistent access.

## Impact

This vulnerability presents a high risk to organizational security, as it allows for trivial and unauthenticated account takeover of any user within the managed realm. This can lead to unauthorized access to sensitive corporate applications, potential exfiltration of proprietary data, and the compromise of administrative accounts that manage the identity provider itself. Because Keycloak often acts as a centralized SSO solution, the impact of a successful attack is magnified across all integrated services.

## Recommendation

- Identify all instances of Red Hat Build of Keycloak and Red Hat JBoss EAP Expansion Pack within the environment using asset inventory tools.
- Apply the latest security patches provided by Red Hat for the affected keycloak-services package as soon as they become available.
- Review authentication and access logs for unusual patterns of password reset requests or unexpected administrative logins.
- Prioritize the hardening of Keycloak instances by restricting network access to reset endpoints where possible until patching is completed.
- Monitor for anomalous API traffic or high volumes of POST requests to credential reset endpoints.
