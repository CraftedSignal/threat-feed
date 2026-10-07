---
title: Okta AiTM Session Cookie Replay Attacks
slug: 2026-10-okta-aitm-session-replay
description: Adversary-in-the-Middle (AiTM) phishing attacks leverage reverse proxies to capture and replay authenticated Okta session cookies, bypassing multi-factor authentication (MFA) protections.
date: "2026-10-07T22:33:32Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Scattered Spider
  - UNC3944
  - Octo Tempest
  - Roasted 0ktapus
  - Muddled Libra
  - Star Fraud
tags:
  - credential-access
  - identity-security
  - phishing
  - okta
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: AiTM attacks capture session cookies via phishing proxies (e.g., Evilginx, Modlishka) and replay them from attacker infrastructure, bypassing MFA.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550.004
    technique_name: Web Session Cookie
    evidence: Attackers then replay these captured cookies from their own infrastructure to hijack authenticated sessions.
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/okta-sso-accounts-targeted-in-vishing-based-data-theft-attacks/
  - https://reliaquest.com/blog/threat-spotlight-shinyhunters-data-breach-targets-salesforce-amid-scattered-spider-collaboration/
  - https://securitylabs.datadoghq.com/articles/investigating-an-aitm-phishing-campaign-m365-okta/
  - https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
  - https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security
---

Adversary-in-the-Middle (AiTM) phishing attacks targeting Okta represent a significant risk to enterprise identity security. By utilizing reverse proxy toolkits such as Evilginx or Modlishka, attackers intercept the entire authentication flow between the legitimate user and the Okta identity provider. Once the user completes their MFA challenge, the attacker captures the resulting session cookie. 

The threat manifests in the post-capture phase where attackers replay these cookies from their own infrastructure. These sessions often exhibit anomalous behavior, such as originating from geographically distinct locations compared to the initial login or utilizing programmatic user agents (e.g., python-requests, curl, or headless browsers) that are inconsistent with typical web browser access. This technique allows attackers to hijack active sessions and gain unauthorized access to critical downstream SaaS and cloud applications, often leading to data exfiltration or further lateral movement within the victim environment.

## Attack Chain

1. Attacker deploys a phishing proxy (e.g., Evilginx) configured to intercept requests for the organization's Okta login portal.
2. Victim receives a vishing or phishing lure leading them to the attacker-controlled proxy domain.
3. Victim provides credentials and completes MFA via the proxy, which forwards the traffic to the legitimate Okta service.
4. Attacker-controlled proxy captures the legitimate session cookie issued by Okta upon successful authentication.
5. Attacker imports the captured cookie into their own environment and re-accesses the target service.
6. Okta receives authentication requests from the attacker infrastructure, which may originate from a different IP or exhibit a non-browser user agent.
7. Attacker gains unauthorized access to protected applications using the hijacked session.

## Impact

Successful AiTM attacks result in full account takeover, bypassing MFA controls. Observed impacts include unauthorized access to high-value services such as Salesforce, AWS, and corporate email systems. This technique has been linked to significant data breaches and identity-based fraud, impacting organizations across multiple sectors.

## Recommendation

Prioritized actions for detection and mitigation:
- Deploy the provided ES|QL rule to monitor Okta system logs for session anomalies, specifically focusing on session replay events with programmatic user agents (python-requests, curl, headless browsers).
- Immediately terminate all active sessions for any user identified as exhibiting anomalous IP or user-agent patterns.
- Require password resets and MFA re-enrollment for compromised accounts to invalidate existing session tokens.
- Implement Okta sign-on policies that restrict sessions based on risk scores, anomalous location, or device context.
- Review email security and proxy logs to identify the origin of the phishing/vishing lures used to initiate the proxy session.
