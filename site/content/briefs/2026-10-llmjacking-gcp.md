---
brief_id: brief-2026-10-20-llmjacking-gcp
event_id: brief-2026-10-20-llmjacking-gcp
revision: 1
activity_at: "2026-10-20T23:53:02Z"
title: 'Google Cloud Platform: Billing account hijacking for unauthorized AI usage'
slug: 2026-10-llmjacking-gcp
description: Threat actors are hijacking Google Cloud Platform billing accounts via phishing and policy manipulation to conduct large-scale, unauthorized LLM inference, resulting in significant financial losses for victims.
date: "2026-10-20T23:53:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:google:google_cloud_platform:*:*:*:*:*:*:*:*
tags:
  - cloud-security
  - phishing
  - billing-fraud
  - identity-compromise
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: The attack began with a classic yet efficient phishing tactic. The threat actor purchased Google Search ads for common administrative search terms.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.003
    subtechnique_name: Cloud Account
    evidence: With domain restrictions lifted, the compromised user account was leveraged to add external actor-controlled Gmail accounts directly into the organization's billing account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.001
    subtechnique_name: Additional Cloud Credentials
    evidence: The role roles/billing.admin granted full control over the billing account, including the ability to manage permissions, attach external projects, and alter payment settings.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: In each of the intrusions investigated, Wiz CIRT observed that after the initial login, subsequent threat actor activity shifted to originate from IP addresses geolocated within each victim organization's headquartered country.
    confidence_band: high
references:
  - https://www.wiz.io/blog/from-phishing-to-llmjacking
iocs:
  - type: ip
    value: 212.73.134.136
  - type: domain
    value: '*.gboogl.com'
  - type: domain
    value: '*.groosl.com'
  - type: domain
    value: '*.gprokl.com'
  - type: domain
    value: '*.gxoosl.com'
  - type: domain
    value: '*.gsoolg.com'
  - type: domain
    value: gzoozl.com
  - type: domain
    value: groonl.com
  - type: domain
    value: gsool.space
  - type: domain
    value: gbrokl.space
  - type: domain
    value: gbrokl.xyz
  - type: domain
    value: gsoosl.xyz
  - type: domain
    value: gsool.xyz
  - type: domain
    value: gpoosl.com
  - type: domain
    value: groolg.com
  - type: domain
    value: gcslom.com
  - type: domain
    value: gcoalg.com
ioc_counts:
  domain: 16
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Hunt for logins from IP 212.73.134.136 in GCP and Google Workspace audit logs.
      owner: SOC
      due: 24h
      evidence: Source lists this as infrastructure seen in initial phishing logins.
  hunt_leads:
    - lead: Identify modification of organization policy "iam.allowedPolicyMemberDomains".
      technique_id: T1098
      data_needed:
        - GCP Admin Activity Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The threat actor deleted safety policies at the organization level, such as iam.allowedPolicyMemberDomains.
  mitigation_plan:
    - priority: immediate
      action: Implement strict identity governance and multi-factor authentication (MFA) enforcement across all GCP administrator accounts.
      owner: IT Operations
      addresses: Initial Access
      evidence: Attacker used phishing to bypass standard authentication.
---

The Wiz Customer Incident Response Team (CIRT) has identified a trend where threat actors compromise Google Cloud Platform (GCP) credentials to hijack billing accounts for unauthorized AI resource consumption. By leveraging phishing campaigns via sponsored search ads, attackers obtain valid user credentials and MFA codes. Once access is gained, they perform privilege escalation and modify organizational policies, such as 'iam.allowedPolicyMemberDomains', to remove guardrails that restrict IAM membership to verified domains. This allows the integration of external, attacker-controlled accounts. The attackers then link external GCP projects to the victim's billing account. By executing AI workloads within these foreign projects, the actors obfuscate their prompts and outputs from the victim's visibility while simultaneously billing the victim for all API usage. This 'LLMjacking' activity leads to rapid billing surges, often reaching hundreds of thousands of dollars within 48 hours of initial compromise.

## Attack Chain

1. Attacker purchases sponsored search ads for terms like "google cloud" to host phishing kits on Google Sites.
2. Victim clicks the malicious ad, provides credentials and MFA tokens on a deceptive login page, which captures the data and redirects to a legitimate Google prompt.
3. Attacker uses harvested credentials to initiate login, bypassing MFA through the captured session data.
4. Attacker enables the Gemini API in existing, low-usage projects and creates service accounts with high-privileged roles (e.g., 'roles/ml.admin').
5. Attacker dismantles organizational policies by deleting 'iam.allowedPolicyMemberDomains' to allow external account access.
6. Attacker invites external attacker-controlled accounts to the organization's billing account and assigns the 'roles/billing.admin' role.
7. Attacker links their external GCP projects to the victim's billing account to offload AI API costs.
8. Attacker demotes original billing administrators to 'viewer' roles to prevent detection and reclamation of administrative control.

## Impact

Victim organizations in the cloud sector have faced significant financial damage, with unauthorized Gemini API charges reaching tens to hundreds of thousands of dollars within 48 hours. Because workloads are executed in foreign projects, organizations lack visibility into the nature of the data being processed, creating both financial and data security risks.

## Recommendation

* Monitor Google Workspace and GCP audit logs for logins originating from the documented IP infrastructure (212.73.134.136).
* Regularly audit GCP IAM configurations for unexpected additions of external domains or personal email addresses (e.g., @gmail.com) to high-privileged roles.
* Audit GCP organization policies for modifications to 'iam.allowedPolicyMemberDomains', as this is a primary indicator of disabling organizational guardrails.
* Monitor for unexpected enabling of the Gemini API product in projects, especially those with minimal historical activity.
* Proactively audit billing account permissions to ensure only authorized corporate identities hold 'roles/billing.admin' or other administrative roles.
