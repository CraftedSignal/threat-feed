---
title: EvilTokens Phishing-as-a-Service Platform Analysis
slug: 2026-09-eviltokens
description: EvilTokens is a Phishing-as-a-Service (PhaaS) platform operated by threat actor Storm-2992 that facilitates adversary-in-the-middle (AiTM) attacks by abusing OAuth device code authentication flows to compromise user accounts.
date: "2026-09-22T20:01:22Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-2992
tags:
  - phishing
  - cloud-security
  - oauth
  - bec
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Office 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Targets are lured through deceptive emails that use 44 different themes, including invoices and request for proposals (RFPs), or shared files.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: EvilTokens enabled threat actors to abuse the device code authentication flow, steal tokens, and compromise organizational accounts.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Stolen tokens are used for email exfiltration and persistence, often through the creation of malicious inbox rules that conceal communications.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/
  - https://aka.ms/ETDisruption
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Management
  immediate_actions:
    - action: Audit and scope Conditional Access policies to restrict device code flow to specific service accounts.
      owner: Identity Management
      due: 48h
      evidence: Microsoft recommends blocking device code flow wherever possible.
  mitigation_plan:
    - priority: immediate
      action: Disable device code flow for all user accounts and restrict access to sanctioned Teams conferencing devices.
      owner: Identity Management
      addresses: OAuth device code flow abuse
      evidence: Microsoft recommends blocking device code flow wherever possible.
---

EvilTokens is a sophisticated Phishing-as-a-Service (PhaaS) platform that emerged in February 2026, enabling threat actors to conduct large-scale business email compromise (BEC) campaigns. Managed by the actor identified as Storm-2992, the platform provides an AI-driven infrastructure to automate the delivery of phishing lures and the analysis of compromised mailboxes. The service utilizes a multi-stage delivery pipeline to bypass traditional email security gateways and targets OAuth device code authentication flows. By manipulating users into authorizing malicious device codes, attackers can effectively circumvent multifactor authentication (MFA) and gain persistent access to organizational accounts. With over 12,000 inboxes compromised across 10,000 organizations, EvilTokens represents a significant risk to cloud productivity environments. The platform's capabilities include prebuilt templates, AI-assisted target reconnaissance, and automated tools for inbox rule creation to maintain long-term persistence and exfiltrate sensitive data.

## Attack Chain

1. The attacker distributes phishing emails containing malicious URLs, PDF attachments, or HTML files designed to bypass email security gateways.
2. The victim is lured to a malicious landing page that presents a deceptive device code authentication prompt.
3. The victim enters a provided short code into their browser, unknowingly authorizing an attacker-controlled session.
4. The platform captures the authorized session token, allowing the attacker to impersonate the user without possessing credentials or completing MFA.
5. The attacker performs reconnaissance within the victim's environment using Microsoft Graph to map organizational structure and permissions.
6. The attacker uses AI-assisted tools to search the compromised mailbox for high-value targets and context for further phishing lures.
7. The attacker establishes persistence by creating malicious inbox rules to conceal ongoing communications and potentially granting access to new malicious devices.
8. The attacker exfiltrates data from the compromised mailbox, continuing to operate while the stolen token remains valid.

## Impact

The EvilTokens platform has impacted over 12,000 inboxes across 10,000 organizations, specifically targeting sectors such as financial services, higher education, healthcare, construction, and wholesale distribution. Successful exploitation results in account takeover, unauthorized access to sensitive corporate information via email exfiltration, and the establishment of durable persistence mechanisms that are difficult for standard security tools to detect.

## Recommendation

Prioritize the following technical controls to mitigate device code phishing:

* Implement Conditional Access policies to strictly scope device code flow usage to authorized Teams device resource accounts only.
* Disable the device code authentication flow organization-wide if it is not explicitly required for hardware-based conferencing solutions.
* Configure security policies to exclude the Device Registration Service resource from any exceptions to ensure MFA enforcement.
* Deploy spoof protections and mail flow rules to identify and block phishing messages leveraging unauthorized third-party connectors.
