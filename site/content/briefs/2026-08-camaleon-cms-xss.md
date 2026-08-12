---
title: Stored Cross-Site Scripting in CamaleonCMS cama_contact_form Plugin
slug: 2026-08-camaleon-cms-xss
description: An authenticated stored cross-site scripting vulnerability in the CamaleonCMS cama_contact_form plugin allows attackers to inject malicious HTML and JavaScript, enabling session takeover and unauthorized administrative actions.
date: "2026-08-12T20:58:52Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - CamaleonCMS
products:
  - cama_contact_form
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can persist malicious script payloads into the database that execute in victims' browsers when the contact form loads.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.001
    technique_name: Stored Data Manipulation
    evidence: Authenticated attackers can inject arbitrary HTML by submitting unsanitized content to the before_html field.
    confidence_band: high
cves:
  - id: CVE-2026-73332
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73332
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CamaleonCMS / cama_contact_form to remediate CVE-2026-73332
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73332
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the contact form edit endpoint to authorized admin users only
      owner: IT Operations
      addresses: CVE-2026-73332
      evidence: Source notes the endpoint lacks proper authorization controls
---

CamaleonCMS contains a stored cross-site scripting (XSS) vulnerability (CVE-2026-73332) within the cama_contact_form plugin. The vulnerability arises from improper input sanitization and insufficient authorization controls on the contact form edit endpoint. Authenticated attackers with low-level privileges can submit arbitrary HTML and JavaScript payloads into the 'before_html' field, which are stored in the application database without adequate validation. When administrators or other users view the contact form, the injected scripts execute within the context of their browsers. This flaw facilitates the theft of session cookies, the execution of unauthorized administrative operations, and full session hijacking, posing a significant risk to the integrity and confidentiality of the affected CMS environment.

## Impact

Successful exploitation allows authenticated attackers to elevate their impact by compromising higher-privileged users. The impact includes unauthorized access to administrative functions, potential data exfiltration via forged authenticated requests, and the persistent execution of malicious code in the browsers of users interacting with the CMS.

## Recommendation

- Audit all CamaleonCMS instances for unauthorized modifications to the 'before_html' configuration in contact forms.
- Implement strict server-side input validation and output encoding for all user-controllable fields within the cama_contact_form plugin.
- Review access control lists for the contact form edit endpoint to ensure that only authorized administrative roles can modify form configuration settings.
- Apply patches provided by the CamaleonCMS vendor to address CVE-2026-73332 immediately.
