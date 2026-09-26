---
title: Authorization Bypass in Flowise Chat Message Endpoints
slug: 2026-09-flowise-rbac-vuln
description: Flowise versions up to 3.1.4 are vulnerable to unauthorized access due to missing route-level RBAC checks, allowing low-privileged API keys to read and delete sensitive chat history.
date: "2026-09-26T15:00:42Z"
lastmod: "2026-09-26T15:01:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flowise:flowise:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-security
  - rbac
  - authentication-bypass
  - identity-management
  - sso
vendors:
  - Flowise
products:
  - Flowise (<= 3.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers with valid but low-privileged API keys can access GET and DELETE chat message routes without required flow permissions
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The application identifies users based exclusively on their email address without verifying the authentication provider or subject identifier, allowing an attacker to impersonate any user by leveraging a different SSO provider or local password to claim a target's email address.
    confidence_band: high
cves:
  - id: CVE-2026-100605
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100605
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100607
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review API access logs for excessive or unauthorized GET/DELETE requests to chat endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-100605 vulnerability details
  mitigation_plan:
    - priority: immediate
      action: Patch Flowise to the latest version once released
      owner: IT Operations
      addresses: CVE-2026-100605
      evidence: NVD vulnerability entry
updates:
  - at: "2026-09-26T15:01:14Z"
    level: L2
    summary: added coverage for Flowise (<= 3.1.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100607
---

Flowise versions through 3.1.4 contain a critical authorization vulnerability originating from missing route-level Role-Based Access Control (RBAC) checks on chat message endpoints. This vulnerability allows attackers in possession of low-privileged API keys to bypass intended permission restrictions. By targeting specific GET and DELETE API routes, an unauthorized actor can access chat histories, internal prompts, and model responses, or perform destructive actions by deleting message logs without holding the necessary flow permissions. This defect significantly impacts the confidentiality and integrity of sensitive chat data managed within the Flowise environment. Organizations deploying Flowise should treat this as a high-priority security concern.

## Impact

Successful exploitation allows low-privileged users to bypass access control constraints, leading to the unauthorized exfiltration of sensitive AI prompts and customer chat history. Furthermore, the ability to issue DELETE requests to the message endpoints permits attackers to disrupt or purge chat logs, which may impact audit trails and service availability. 

## Recommendation

* Immediately restrict access to the Flowise API to trusted internal networks while awaiting official patches.
* Audit application logs for abnormal patterns of GET or DELETE requests to chat message endpoints originating from known low-privileged service accounts or API keys.
* Upgrade to the latest version of Flowise as soon as a security update is released by the maintainer.
