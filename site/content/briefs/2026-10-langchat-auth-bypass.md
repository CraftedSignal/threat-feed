---
title: Authentication Bypass in LangChat REST API
slug: 2026-10-langchat-auth-bypass
description: A missing Sa-Token interceptor in LangChat allows unauthenticated remote attackers to access sensitive REST controllers, leading to full system compromise and credential exfiltration.
date: "2026-10-16T18:45:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:langchat:langchat:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve
  - api-security
vendors:
  - LangChat
products:
  - LangChat (<= 2a6285a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LangChat contains a missing authentication vulnerability that allows unauthenticated remote attackers to access REST controllers.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials in Files
    evidence: Attackers can query /api/v1/auth/users to read plaintext passwords, retrieve LLM provider API keys.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: Attackers can create super-admin accounts.
    confidence_band: high
cves:
  - id: CVE-2026-111704
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111704
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to the LangChat REST API
      owner: IT Operations
      due: 4h
      evidence: Unauthenticated access via API allows full system control.
  mitigation_plan:
    - priority: immediate
      action: Upgrade LangChat to a version released after commit 2a6285a
      owner: IT Operations
      addresses: CVE-2026-111704
      evidence: Vulnerability exists up to commit 2a6285a.
---

LangChat, an LLM-focused application, contains a critical authentication bypass vulnerability (CVE-2026-111704) affecting all versions up to commit 2a6285a. The vulnerability stems from the absence of a required Sa-Token interceptor, which is responsible for enforcing authentication across the application's REST endpoints. 

By design, the application fails to validate the identity of remote callers when interacting with REST controllers. This flaw exposes the entire API surface, including administrative functions, to unauthenticated actors. Attackers can leverage this exposure to query system endpoints, such as /api/v1/auth/users, to harvest plaintext passwords and API keys associated with configured LLM providers. Furthermore, the lack of access controls allows for the unauthorized creation of super-administrator accounts and arbitrary data manipulation (CRUD) across the platform. This vulnerability poses an immediate risk to any LangChat instance, enabling complete administrative takeover and persistent unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate highly sensitive data, including user plaintext passwords and LLM provider API keys. The ability to create super-admin accounts permits attackers to maintain persistence, modify system configurations, and delete or manipulate critical business data. Organizations utilizing LangChat for LLM orchestration are at risk of secondary supply chain attacks if LLM provider API keys are compromised, potentially leading to unauthorized costs or model poisoning.

## Recommendation

- Immediately restrict network access to the LangChat REST API from untrusted or public-facing network segments until the patch is applied.
- Audit logs for unauthorized requests to the /api/v1/auth/users endpoint or suspicious creation of administrator-level accounts.
- Review and rotate all API keys stored within the LangChat application if the system has been accessible from the internet.
- Upgrade LangChat to a version post-dating commit 2a6285a once a vendor fix is available.
