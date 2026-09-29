---
title: Entra ID Application Credential Modification
slug: 2026-09-entra-id-credential-modification
description: Adversaries may add unauthorized credentials to Entra ID applications to establish persistent access and escalate privileges within cloud environments.
date: "2026-09-29T22:15:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - cloud-security
  - entra-id
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary may abuse this by creating an additional authentication method to evade defenses or persist in an environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may exploit this by adding unauthorized credentials, enabling persistent access or evading defenses.
    confidence_band: high
references:
  - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
  - https://attack.mitre.org/techniques/T1098/001/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity and Access Management
  immediate_actions:
    - action: Monitor Entra ID audit logs for operation name 'Update application - Certificates and secrets management'.
      owner: SOC
      due: 24h
      evidence: Source rule logic identifies this as the primary indicator for credential modification.
  mitigation_plan:
    - priority: immediate
      action: Restrict directory roles with the ability to modify application credentials.
      owner: Identity and Access Management
      addresses: T1098.001
      evidence: Standard identity hygiene practices for mitigating cloud account manipulation.
---

Threat actors target Entra ID (formerly Azure AD) applications by adding unauthorized certificates or secret strings to bypass traditional authentication mechanisms. By modifying application credentials, an adversary can authenticate as the application, enabling them to maintain persistent access or escalate privileges to perform unauthorized actions within the cloud tenant. This technique relies on legitimate administrative functions, making it difficult to distinguish from routine maintenance without baseline awareness. Defenders should monitor for successful modifications to application certificates and secrets, as these events are often indicators of compromise when performed by unexpected identities or outside of established change management windows.

## Attack Chain

1. Attacker gains initial access to an Entra ID tenant via stolen credentials, phishing, or exploitation of an existing service principal.
2. Attacker enumerates applications within the tenant to identify those with high-privileged API permissions or sensitive data access.
3. Attacker uses compromised administrative or application-owner credentials to gain write access to the target application.
4. Attacker performs the "Update application - Certificates and secrets management" operation via the Azure portal, CLI, or PowerShell.
5. Attacker adds a new, attacker-controlled certificate or client secret to the application configuration.
6. Attacker uses the newly added credential to authenticate as the application principal, gaining authorized access to protected cloud resources or graph APIs.
7. Attacker proceeds with malicious objectives such as data exfiltration or internal reconnaissance.

## Impact

Successful exploitation allows for long-term persistent access that survives password resets of individual user accounts. It can lead to unauthorized data access, privilege escalation within the Azure environment, and potential bypass of conditional access policies tied to user accounts, depending on the permissions assigned to the modified application.

## Recommendation

Prioritize the implementation of audit log monitoring for all credential lifecycle events within Entra ID.
- Enable and centralize Entra ID audit logs to monitor the "Update application - Certificates and secrets management" operation.
- Review all active certificates and secrets associated with high-privileged service principals quarterly to identify unrecognized credentials.
- Enforce the principle of least privilege by restricting "Application Administrator" and "Cloud Application Administrator" roles to the minimum number of necessary accounts.
- Configure alerts for any modifications to production-critical applications performed by accounts not associated with an approved CI/CD service principal.
