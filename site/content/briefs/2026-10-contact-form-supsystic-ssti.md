---
brief_id: brief-2026-10-29-contact-form-supsystic-ssti
event_id: brief-2026-10-29-contact-form-supsystic-ssti
revision: 1
activity_at: "2026-10-29T13:19:26Z"
title: 'Contact Form by Supsystic: Server-Side Template Injection (CVE-2026-115301)'
slug: 2026-10-contact-form-supsystic-ssti
description: The Contact Form by Supsystic WordPress plugin before 1.11.1 allows authenticated users to perform server-side template injection via unsandboxed form templates, leading to remote code execution and unauthorized access to sensitive server configuration files.
date: "2026-10-29T13:19:26Z"
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
  validation_status: Source verified; plugin version confirmed
cpes:
  - cpe:2.3:a:supsystic:contact_form:*:*:*:*:*:wordpress:*:*
vendors:
  - Supsystic
products:
  - Contact Form by Supsystic (< 1.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Contact Form by Supsystic WordPress plugin before 1.11.1 does not sandbox the template engine used to render its forms and allows stored form-editor content to reach that engine as executable template code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabling an administrator to perform server-side template injection and execute arbitrary code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-115301
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115301
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Contact Form by Supsystic plugin to 1.11.1 or higher
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is addressed in plugin version 1.11.1
  hunt_leads:
    - lead: Monitor web server access logs for anomalous requests to the WordPress admin or front-end pages triggering template rendering
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The injected template is compiled and executed whenever any visitor loads a page containing the form.
  mitigation_plan:
    - priority: immediate
      action: Update to version 1.11.1
      owner: IT Operations
      addresses: CVE-2026-115301
      evidence: Source states plugin version 1.11.1 contains the fix
---

The Contact Form by Supsystic WordPress plugin versions prior to 1.11.1 contain a vulnerability where the template engine used for rendering forms is not properly sandboxed. This flaw allows an authenticated administrator to inject arbitrary template code into form-editor content. When a visitor subsequently views a page containing the affected form, the injected template is compiled and executed by the server. This permits arbitrary code execution and the unauthorized disclosure of sensitive server-side information, such as authentication salts and database credentials.

## Impact

Successful exploitation allows authenticated attackers to gain remote code execution on the underlying server. Furthermore, the vulnerability impacts unauthenticated visitors, as the stored payload is executed during page rendering, leading to potential exfiltration of environment-specific secrets like database credentials and authentication salts.

## Recommendation

- Upgrade the Contact Form by Supsystic WordPress plugin to version 1.11.1 or later.
- Audit administrative user access within the WordPress dashboard to identify accounts with form-editing permissions that may have been leveraged for this exploit.
- Perform a post-patch review of server configuration files, including 'wp-config.php', for unauthorized modifications or access attempts.
