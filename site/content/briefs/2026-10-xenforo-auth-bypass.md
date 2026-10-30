---
brief_id: brief-2026-10-30-xenforo-auth-bypass
event_id: brief-2026-10-30-xenforo-auth-bypass
revision: 1
activity_at: "2026-10-30T22:04:13Z"
title: 'XenForo: Broken access control in ForceAgreementController (CVE-2026-73318)'
slug: 2026-10-xenforo-auth-bypass
description: XenForo versions prior to 2.3.13 contain an authorization bypass vulnerability (CVE-2026-73318) allowing low-privileged administrative users to trigger site-wide user re-agreement workflows.
date: "2026-10-30T22:04:13Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified against CVE-2026-73318 data.
cpes:
  - cpe:2.3:a:xenforo:xenforo:*:*:*:*:*:*:*:*
vendors:
  - XenForo
products:
  - XenForo (< 2.3.13)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The ACP navigation entries are limited to administrators with the option permission, but ForceAgreementController does not enforce that permission.
    confidence_band: high
cves:
  - id: CVE-2026-73318
    cvss: 3.8
    epss: 0.0049
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-73318
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-73318&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade XenForo to 2.3.13 or later
      owner: IT Operations
      due: 48h
      evidence: XenForo 2.3.13 contains the fix.
  hunt_leads:
    - lead: Identify ACP administrators accessing ForceAgreementController endpoints without sufficient permissions
      technique_id: T1068
      data_needed:
        - XenForo application logs / Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Direct requests from any authenticated ACP administrator reach both forms and their state-changing POST actions.
  mitigation_plan:
    - priority: immediate
      action: Apply XenForo 2.3.13 patch
      owner: IT Operations
      addresses: CVE-2026-73318
      evidence: XenForo 2.3.13 contains the fix.
---

CVE-2026-73318 is an authorization bypass vulnerability affecting the `ForceAgreementController` in XenForo versions before 2.3.13. The vulnerability allows an administrator with limited ACP access - who lacks the specific 'option' permission - to access and execute site-wide policy and terms re-agreement workflows. This action resets global policy acceptance timestamps, forcing all board users to re-agree to terms. The vulnerability does not permit the modification of policy text.

## Impact

Successful exploitation allows a low-privileged administrator to disrupt user activity by forcing site-wide re-agreement gates. This does not provide full system compromise or unauthorized access to user data beyond triggering the UI agreement prompt.

## Recommendation

* Patch XenForo immediately by upgrading to version 2.3.13 or later.
* Audit ACP administrator permissions to ensure only authorized personnel hold the 'option' capability.
* Monitor ACP administrative access logs for unauthorized attempts to access `ForceAgreementController` endpoints.
