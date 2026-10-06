---
title: Remote Code Execution in ACPT (Premium) WordPress Plugin
slug: 2026-10-acpt-rce
description: Authenticated attackers with subscriber-level access can achieve remote code execution in ACPT (Premium) versions up to 2.0.66 by injecting malicious Twig expressions via the REST API.
date: "2026-10-06T08:53:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acpt:acpt:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - rce
  - web-application
  - cve-2026-105701
vendors:
  - ACPT
products:
  - ACPT (Premium) (<= 2.0.66)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is due to missing capability check on the REST API form creation endpoint and unsandboxed Twig environment rendering email templates.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-105701
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105701
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade ACPT (Premium) plugin to a version beyond 2.0.66.
      owner: IT Operations
      addresses: CVE-2026-105701
      evidence: Source states vulnerability exists in versions up to 2.0.66.
---

The ACPT (Premium) plugin for WordPress contains a critical vulnerability (CVE-2026-105701) that allows authenticated attackers with subscriber-level access or higher to execute arbitrary code on the underlying server. The flaw exists due to a missing capability check on the REST API endpoint responsible for form creation. This endpoint fails to properly validate the user's permissions, allowing the injection of malicious payloads within the email_settings parameter. Because the plugin utilizes an unsandboxed Twig template rendering environment for these email templates, an attacker can craft specifically formatted Twig expressions that are executed server-side. This vulnerability affects all versions of the ACPT (Premium) plugin up to and including 2.0.66. Successful exploitation requires an attacker to first create a malicious form object via the REST API and then trigger the form submission process, which forces the rendering engine to process the injected code.

## Impact

Successful exploitation results in full Remote Code Execution (RCE) on the WordPress server. As WordPress typically runs with the permissions of the web server user (such as www-data), an attacker can read sensitive files, modify site content, pivot to the internal network, or deploy persistent backdoors. Given the ubiquity of WordPress installations, this vulnerability poses a high risk for sites utilizing the ACPT Premium plugin for form management.

## Recommendation

- Upgrade the ACPT (Premium) plugin to a version released after 2.0.66 immediately to receive the security patch.
- Audit logs for unauthorized POST requests to WordPress REST API endpoints related to form creation from accounts with subscriber-level permissions.
- Implement strict server-side input validation and restrict access to the REST API if specific plugins do not require external visibility.
