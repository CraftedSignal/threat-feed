---
brief_id: brief-2026-11-02-munshi-auth-bypass
event_id: brief-2026-11-02-munshi-auth-bypass
revision: 1
activity_at: "2026-11-02T19:48:22Z"
title: 'Munshi: Missing authorization in company deletion (CVE-2026-119733)'
slug: 2026-11-munshi-auth-bypass
description: An authorization vulnerability in the Munshi company deletion workflow allows authenticated sub-users to permanently delete company records and associated data without the required permissions.
date: "2026-11-02T19:48:22Z"
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
  validation_status: Source verified against NVD data
cpes:
  - cpe:2.3:a:petpooja:munshi:*:*:*:*:*:*:*:*
vendors:
  - Petpooja
products:
  - Munshi (< 2026-07-07)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: An authenticated invited sub-user with mere access to a company can exploit this flaw to perform a hard delete of the company record, causing irreversible loss of associated business data.
    confidence_band: high
cves:
  - id: CVE-2026-119733
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119733
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Munshi to version released on 2026-07-07 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability fixed in releases from 2026-07-07 onwards
  hunt_leads:
    - lead: Audit API logs for DELETE requests to /api/companies/{company_id} originating from non-administrative sub-user accounts
      technique_id: T1531
      data_needed:
        - Web server access logs
        - Application authorization audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Application fails to enforce the dedicated company_delete permission at DELETE /api/companies/{company_id}
  mitigation_plan:
    - priority: immediate
      action: Apply patch released 2026-07-07
      owner: IT Operations
      addresses: CVE-2026-119733
      evidence: NVD source confirms vulnerability exists before 2026-07-07
---

Munshi by Petpooja versions prior to 2026-07-07 contain a missing authorization vulnerability in the `DELETE /api/companies/{company_id}` endpoint. The application fails to validate the `company_delete` permission or verify company ownership during the deletion process. An authenticated sub-user with minimal access can exploit this flaw to execute a hard delete of a company record, resulting in irreversible data loss, including invoices, configurations, and chat sessions.

## Impact
Exploitation leads to permanent, irreversible deletion of business data, including financial records, system configurations, and historical communications.

## Recommendation
- Upgrade Munshi to the version released on 2026-07-07 or later to implement proper authorization checks on the company deletion API.
- Review access control lists for all sub-user accounts to identify accounts with excessive or unnecessary permissions.
- Audit administrative access logs for the deletion endpoint to ensure no unauthorized records have been purged.
