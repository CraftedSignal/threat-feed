---
brief_id: brief-2026-10-25-phpmyfaq-auth-bypass
event_id: brief-2026-10-25-phpmyfaq-auth-bypass
revision: 1
activity_at: "2026-10-25T14:32:35Z"
title: 'phpMyFAQ: Object-level authorization bypass (CVE-2026-116183)'
slug: 2026-10-phpmyfaq-auth-bypass
description: An object-level authorization bypass in phpMyFAQ versions prior to 4.1.10 allows unauthenticated attackers to modify or delete visitor questions via the API.
date: "2026-10-25T14:32:35Z"
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
  validation_status: Source documentation confirmed; vulnerability logic requires web server log monitoring for exploitation attempts.
cpes:
  - cpe:2.3:a:phpmyfaq:phpmyfaq:*:*:*:*:*:*:*:*
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (< 4.1.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: phpMyFAQ before 4.1.10 contains an object-level authorization bypass vulnerability that allows unauthenticated attackers to modify or delete any visitor question.
    confidence_band: high
cves:
  - id: CVE-2026-116183
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116183
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade phpMyFAQ to 4.1.10 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor release fixes the underlying authorization bypass.
  hunt_leads:
    - lead: Monitor web server logs for POST requests to /api/faq/create containing arbitrary openQuestionID values
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attackers exploit this by supplying an arbitrary openQuestionID to POST /api/faq/create.
  mitigation_plan:
    - priority: immediate
      action: Disable records.enableDeleteQuestion in the configuration
      owner: IT Operations
      addresses: CVE-2026-116183
      evidence: Attackers can permanently delete questions when records.enableDeleteQuestion is enabled.
---

phpMyFAQ versions prior to 4.1.10 contain an object-level authorization bypass vulnerability (CVE-2026-116183). The vulnerability resides in the `POST /api/faq/create` endpoint, where insufficient validation of the `openQuestionID` parameter allows unauthenticated actors to modify or delete visitor questions. Successful exploitation requires solving the CAPTCHA and allows attackers to rewrite categories, forge entries in `faqquestion_history`, or delete questions if the `records.enableDeleteQuestion` configuration is active.

## Impact
Unauthorized modification or deletion of visitor questions, manipulation of question categories, and potential corruption of question history records.

## Recommendation
* Upgrade phpMyFAQ to version 4.1.10 or later immediately.
* If patching is delayed, audit web server logs for suspicious POST requests to `/api/faq/create` containing `openQuestionID` parameters.
* Disable `records.enableDeleteQuestion` in the application configuration to prevent unauthorized question deletion until the patch is applied.
