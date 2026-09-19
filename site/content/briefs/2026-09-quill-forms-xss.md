---
title: Stored XSS in Quill Forms WordPress Plugin
slug: 2026-09-quill-forms-xss
description: The Quill Forms WordPress plugin (<= 5.7.1) contains a stored cross-site scripting vulnerability that allows unauthenticated attackers to inject malicious JavaScript via form entry fields.
date: "2026-09-19T10:11:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quill_forms:conversational_multi_step_forms_surveys_quizzes:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - xss
  - web-application
vendors:
  - Quill Forms
products:
  - Quill Forms | Conversational Multi Step Forms, Surveys & quizzes (<= 5.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-15664
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15664
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Quill Forms plugin to a version greater than 5.7.1
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to, and including, 5.7.1.
  mitigation_plan:
    - priority: immediate
      action: Update Quill Forms plugin to version 5.7.2 or later
      owner: IT Operations
      addresses: CVE-2026-15664
      evidence: Source states all versions up to 5.7.1 are vulnerable.
---

The Quill Forms | Conversational Multi Step Forms, Surveys & quizzes plugin for WordPress (versions 5.7.1 and below) contains a stored cross-site scripting (XSS) vulnerability. The issue arises from insufficient sanitization and escaping of the 'Other' value field within Multiple Choice form elements. This allows an unauthenticated remote attacker to submit malicious payloads through publicly accessible forms. When a WordPress administrator accesses the form results page within the dashboard, the payload is rendered and executes in the context of their active session. This can lead to unauthorized actions performed on behalf of the administrator, such as creating new administrative accounts, modifying site settings, or exfiltrating sensitive session tokens.

## Impact

The vulnerability targets administrative accounts reviewing form submissions. Successful exploitation grants attackers the ability to execute arbitrary JavaScript within the WordPress admin dashboard, potentially leading to full site takeover.

## Recommendation

Update the Quill Forms plugin to the latest patched version immediately. Monitor web server logs for HTTP POST requests to form submission endpoints containing JavaScript keywords or HTML tags within the 'Other' input parameters.
