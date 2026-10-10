---
title: Account Takeover Vulnerability in SkillHub AccountMergeService
slug: 2026-10-skillhub-auth-bypass
description: SkillHub versions prior to 0.2.22 contain an incorrect authorization vulnerability allowing authenticated attackers to perform account takeovers by exploiting the account merge flow.
date: "2026-10-10T15:55:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:skillhub:skillhub:*:*:*:*:*:*:*:*
vendors:
  - SkillHub
products:
  - SkillHub (< 0.2.22)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SkillHub before 0.2.22 contains an incorrect authorization vulnerability in AccountMergeService... that allows authenticated attackers to take over other accounts.
    confidence_band: high
cves:
  - id: CVE-2026-108550
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108550
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SkillHub to version 0.2.22 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure for CVE-2026-108550
  hunt_leads:
    - lead: Unusual activity in account merge logs
      technique_id: T1068
      data_needed:
        - Application logs showing merge initiation and confirmation
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exists in AccountMergeService/Controller
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 0.2.22
      owner: IT Operations
      addresses: CVE-2026-108550
      evidence: Vulnerability fix requires update to 0.2.22
---

SkillHub versions prior to 0.2.22 contain a critical incorrect authorization vulnerability within the AccountMergeService and AccountMergeController components. This flaw allows an authenticated attacker to manipulate the account merge process to hijack the identity of another user. By submitting a crafted request to the merge initiation endpoint with a target username or OAuth identifier, an attacker can directly obtain the verification token required to complete the merge. Successfully exploiting this vulnerability grants the attacker full control over the victim's account, including the inheritance of associated API tokens, user roles, and namespace ownership. This represents a significant risk for multi-tenant environments or systems relying on SkillHub for centralized identity management, as it facilitates rapid privilege escalation and lateral movement across organizational resources.

## Attack Chain

1. Attacker gains access to a low-privileged account within the SkillHub environment.
2. Attacker identifies the account merge initiation endpoint via API documentation or reverse engineering.
3. Attacker crafts an HTTP POST request targeting the merge service.
4. Attacker inserts the victim's username or OAuth identity into the request parameters.
5. The vulnerable AccountMergeService fails to validate the authorization of the requestor against the target identity.
6. Attacker intercepts the verification token returned by the server.
7. Attacker submits the verification token to the merge confirmation endpoint.
8. Attacker inherits the victim's privileges, gaining access to roles, API tokens, and namespace ownership.

## Impact

Successful exploitation allows for complete account takeover, resulting in unauthorized access to sensitive data, potential exfiltration of proprietary information via inherited API tokens, and administrative takeover of namespaces. The impact is significant for organizations utilizing SkillHub for integrated access control, as it allows attackers to bypass identity boundaries and assume the permissions of high-privilege users or service accounts.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Upgrade all instances of SkillHub to version 0.2.22 or later immediately to resolve CVE-2026-108550.
- Audit logs for the account merge initiation and confirmation endpoints to identify anomalous spikes in account merge activity.
- Review account permissions and namespace ownership logs for any suspicious modifications performed by non-admin users.
