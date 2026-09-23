---
title: Unauthenticated Submission Overwrite in Formie Plugin for Craft CMS
slug: 2026-09-formie-submission-hijacking
description: The Formie plugin for Craft CMS is vulnerable to an unauthenticated submission hijacking flaw (CVE-2026-76087) where attackers can overwrite other users' in-progress forms by supplying arbitrary submission IDs.
date: "2026-09-23T19:57:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:verbb:formie:*:*:*:*:*:craft_cms:*:*
vendors:
  - Verbb
products:
  - Formie (3.0.0 - 3.1.30)
  - Formie (< 2.2.23)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: An unauthenticated attacker could enumerate sequential submission IDs and overwrite or hijack another user's in-progress submission.
    confidence_band: high
cves:
  - id: CVE-2026-76087
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-584p-f93j-wpgc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76087
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Verbb Formie to 3.1.31 or 2.2.23.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 3.1.31 (Craft 5) and 2.2.23 (Craft 4).
  hunt_leads:
    - lead: Look for high volumes of POST requests to /actions/formie/submissions/submit from single IP addresses.
      technique_id: T1595
      data_needed:
        - Web server logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker could enumerate sequential submission IDs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched versions.
      owner: IT Operations
      addresses: CVE-2026-76087
      evidence: Fixed in 3.1.31 (Craft 5) and 2.2.23 (Craft 4).
---

The Formie plugin for Craft CMS is susceptible to an unauthenticated submission hijacking vulnerability, tracked as CVE-2026-76087. The vulnerability exists within the `formie/submissions/submit` action, which fails to verify that the submission ID provided by the client belongs to the active user's session. Specifically, the `SubmissionsController::actionSubmit` method trusts the user-supplied `submissionId` without enforcing ownership checks or validating an edit token for incomplete submissions. 

This flaw allows an unauthenticated attacker to enumerate sequential submission IDs and overwrite or hijack the data within another user's in-progress, incomplete submission. If an attacker successfully overwrites the submission data, the corrupted or malicious entries are persisted and eventually forwarded through the form's integrated notification systems when the victim completes the form. This issue represents an incomplete fix for a previously identified vulnerability (GHSA-pgxq-p76c-x9cg). Defenders should prioritize upgrading to the patched versions immediately as no reliable workarounds exist.

## Impact

The vulnerability allows unauthorized parties to manipulate form data entered by legitimate users. If exploited, attackers can inject malicious content into submissions that are then processed by the target's backend integrations or notification systems. This impacts organizations using Formie for critical data collection, such as lead generation, registrations, or application forms. Because the data is forwarded to integrations upon completion, attackers can effectively facilitate exfiltration of sensitive information or manipulate business workflows.

## Recommendation

- Upgrade to Formie 3.1.31 or later for Craft 5, or 2.2.23 or later for Craft 4, to apply the mandatory ownership and token validation checks.
- Review web server access logs for anomalous patterns of sequential POST requests to the `formie/submissions/submit` endpoint, particularly those originating from unauthorized sessions.
- Audit form notification logs for submissions that contain suspicious, unexpected, or non-user-supplied data values.
