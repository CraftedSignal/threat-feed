---
brief_id: brief-2026-11-11-everest-forms-file-read
event_id: brief-2026-11-11-everest-forms-file-read
revision: 1
activity_at: "2026-11-11T05:59:22Z"
title: 'Everest Forms: Arbitrary file read in Pro add-on (CVE-2026-115483)'
slug: 2026-11-everest-forms-file-read
description: The Everest Forms plugin for WordPress (Pro add-on) contains an arbitrary file read vulnerability that allows unauthenticated attackers to exfiltrate sensitive files by manipulating email notification attachments.
date: "2026-11-11T05:59:22Z"
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
  validation_status: Source verified; environment validation required
cpes:
  - cpe:2.3:a:everestforms:everest_forms:*:*:*:*:*:wordpress:*:*
vendors:
  - Everest Forms
products:
  - Everest Forms Pro (<= 3.6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Everest Forms plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 3.6.3 via the attach_entry_files() function.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server... exfiltrated file is delivered to the attacker.
    confidence_band: high
cves:
  - id: CVE-2026-115483
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115483
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Everest Forms Pro to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-115483
  hunt_leads:
    - lead: Identify form submissions containing arbitrary file paths in fields mapped to signature meta keys
      technique_id: T1190
      data_needed:
        - Web server access logs
        - WordPress plugin activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability arises from improper path validation when attaching files matching the /signature_/ meta key pattern
  mitigation_plan:
    - priority: immediate
      action: Disable email notifications or the Pro signature field until the plugin is updated
      owner: IT Operations
      addresses: CVE-2026-115483
      evidence: Exploitation requires a form whose email notification has the Attach Files setting enabled
---

Everest Forms plugin versions up to and including 3.6.3 contain an arbitrary file read vulnerability (CVE-2026-115483) within the `attach_entry_files()` function. The flaw occurs because the function performs a `file_exists()` check on entry fields with meta keys matching the pattern `/signature_/` without validating or restricting the file path before attaching them to notification emails. Exploitation requires the use of the Everest Forms Pro add-on, which provides the necessary signature field and email attachment functionality.

## Impact
An unauthenticated attacker can exfiltrate sensitive server-side files, such as `wp-config.php`, which may contain database credentials and other configuration secrets. The exfiltrated data is delivered directly to an attacker-controlled email address via the plugin notification system.

## Recommendation
- Update Everest Forms Pro to the latest available version containing the security fix for CVE-2026-115483.
- Review form notification settings for any fields configured to use the "Signature" or similar fields that could be abused for file attachment.
- Audit web server access logs for anomalous POST requests directed at form submission endpoints that result in repeated email notification triggers.
