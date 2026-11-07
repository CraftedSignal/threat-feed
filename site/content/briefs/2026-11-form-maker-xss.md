---
brief_id: brief-2026-11-07-form-maker-xss
event_id: brief-2026-11-07-form-maker-xss
revision: 1
activity_at: "2026-11-07T03:46:33Z"
title: 'Form Maker by 10Web: Stored Cross-Site Scripting (CVE-2026-120512)'
slug: 2026-11-form-maker-xss
description: The Form Maker by 10Web WordPress plugin up to version 1.15.50 contains a stored XSS vulnerability that allows unauthenticated attackers to inject malicious scripts into hidden input fields, which execute when an administrator interacts with the map view feature.
date: "2026-11-07T03:46:33Z"
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
  validation_status: Source verified, no technical gaps identified.
cpes:
  - cpe:2.3:a:10web:form_maker:*:*:*:*:*:wordpress:*:*
vendors:
  - 10Web
products:
  - Form Maker by 10Web – Mobile-Friendly Drag & Drop Contact Form Builder (<= 1.15.50)
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
    evidence: The attacker-controlled field_id value is echoed unescaped into a single-quoted JavaScript string.
    confidence_band: high
cves:
  - id: CVE-2026-120512
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120512
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Form Maker by 10Web to version 1.15.51 or higher.
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions are <= 1.15.50.
  hunt_leads:
    - lead: Identify abnormal form submission data containing script tags, "javascript:", or event handlers in hidden fields.
      technique_id: T1190
      data_needed:
        - WordPress database entries for the plugin (wp_wdform_submits or similar tables)
        - Web application firewall logs for POST requests to form submission endpoints
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves injecting arbitrary web scripts into hidden input fields via form submissions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to the latest version.
      owner: IT Operations
      addresses: CVE-2026-120512
      evidence: NVD advisory states <= 1.15.50 is vulnerable.
---

The Form Maker by 10Web WordPress plugin is vulnerable to stored Cross-Site Scripting (XSS) due to insufficient input sanitization and output escaping in hidden input fields (parameters formatted as `wdform_<n>_element<id>`). An unauthenticated attacker can submit malicious payloads through contact forms. The script executes in the context of an administrator's session when they view the submissions screen and select the "Show-on-Map" feature for a malicious entry. This process bypasses nonces and capability checks by utilizing the administrator's own active session and the `fm_ajax_nonce` provided by the application.

## Attack Chain

1. Attacker identifies a target WordPress site running a vulnerable version of the Form Maker plugin.
2. Attacker crafts a malicious form submission containing XSS payloads within hidden input fields.
3. Attacker submits the form to the target application.
4. The plugin stores the payload in the database without proper sanitization.
5. An administrator navigates to the 'Submissions' screen within the WordPress dashboard.
6. The administrator interacts with the 'Show-on-Map' link associated with the malicious submission.
7. The application echoes the payload unescaped into a JavaScript string within the `FormMakerEditCountryinPopup` popup.
8. The malicious script executes in the administrator's browser, potentially allowing account takeover or further administrative actions.

## Impact

Successful exploitation results in arbitrary script execution in an administrator's browser context, potentially leading to unauthorized administrative actions, sensitive data access, or account takeover.

## Recommendation

- Update the "Form Maker by 10Web - Mobile-Friendly Drag & Drop Contact Form Builder" plugin to the latest available version (beyond 1.15.50) to ensure the sanitization fix is applied.
- Implement or enforce Content Security Policy (CSP) headers to mitigate the impact of XSS vulnerabilities.
- Monitor administrative access to the WordPress dashboard and review plugin submissions for suspicious characters or script tags in hidden fields.
