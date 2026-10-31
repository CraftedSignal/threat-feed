---
brief_id: brief-2026-10-31-ninja-forms-xss-59c0fda1
event_id: brief-2026-10-31-ninja-forms-xss-59c0fda1
revision: 1
activity_at: "2026-10-31T07:51:28Z"
title: 'Ninja Forms: Stored Cross-Site Scripting via formData.extra (CVE-2026-109997)'
slug: 2026-10-ninja-forms-xss-59c0fda1
description: The Ninja Forms WordPress plugin is vulnerable to stored cross-site scripting (XSS) due to improper input sanitization and a flawed nonce implementation in the nf_ajax_submit endpoint, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-10-31T07:51:28Z"
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
  validation_status: Detection rule defined, pending environment validation
cpes:
  - cpe:2.3:a:ninja_forms:contact_form_builder_with_calculators_quizzes_signatures_ai_form_builder:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - wordpress
  - plugin-vulnerability
vendors:
  - Ninja Forms
products:
  - Ninja Forms – Contact Form Builder with Calculators, Quizzes, Signatures & AI Form Builder (<= 3.15.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
cves:
  - id: CVE-2026-109997
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109997
rules:
  - title: Detects CVE-2026-109997 Exploitation - Stored XSS in Ninja Forms
    description: Detects potential exploitation of CVE-2026-109997 via HTTP POST requests to the nf_ajax_submit endpoint containing XSS payloads in the formData.extra parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Ninja Forms plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: Vulnerable in all versions up to, and including, 3.15.5
  hunt_leads:
    - lead: Hunt for anomalous scripts stored in the database
      technique_id: T1059.007
      data_needed:
        - Database table entries for Ninja Forms
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Stored cross-site scripting (XSS) via the formData.extra parameter
  mitigation_plan:
    - priority: immediate
      action: Update Ninja Forms
      owner: IT Operations
      addresses: CVE-2026-109997
      evidence: Vulnerable in all versions up to, and including, 3.15.5
---

Ninja Forms - Contact Form Builder with Calculators, Quizzes, Signatures & AI Form Builder for WordPress (all versions up to and including 3.15.5) contains a stored Cross-Site Scripting (XSS) vulnerability. The flaw exists in the 'formData.extra' parameter. An unauthenticated attacker can exploit this via the 'nf_ajax_submit' endpoint. Due to improper nonce handling, the endpoint issues a valid nonce on request failure, effectively bypassing security protections.

## Impact

Successful exploitation allows unauthenticated attackers to inject arbitrary web scripts into pages. These scripts execute in the context of any user (including administrators) who accesses the injected page, potentially leading to unauthorized actions or credential theft.

## Recommendation

- Upgrade the Ninja Forms plugin to the latest version beyond 3.15.5 immediately.
- Review WordPress access logs for anomalous requests to the 'nf_ajax_submit' endpoint containing suspicious 'formData.extra' parameter content.
- Inspect plugin configuration and form submission entries for injected JavaScript payloads.
