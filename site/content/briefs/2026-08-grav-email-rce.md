---
title: Remote Code Execution in Grav Email Plugin via Twig Injection
slug: 2026-08-grav-email-rce
description: The Grav Email plugin version 4.2.1 and below allows authenticated attackers to achieve remote code execution by injecting malicious Twig expressions into form processing parameters.
date: "2026-08-25T04:06:42Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - getgrav
products:
  - grav-plugin-email
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated remote user... can place a Twig expression... to execute an arbitrary operating-system command.
    confidence_band: high
cves:
  - id: CVE-2026-75574
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75574
  - https://github.com/getgrav/grav/security/advisories/GHSA-gh8j-q67c-j53f
  - https://www.vulncheck.com/advisories/grav-before-remote-code-execution-via-email-twig
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade grav-plugin-email to version 4.2.2 or higher
      owner: IT Operations
      due: 24h
      evidence: Plugin version prior to 4.2.2 is confirmed vulnerable
  mitigation_plan:
    - priority: immediate
      action: Restrict API access to authorized users
      owner: IT Operations
      addresses: CVE-2026-75574
      evidence: Vulnerability requires api.access and api.pages.write permissions
---

The Grav Email plugin (getgrav/grav-plugin-email) prior to version 4.2.2 contains a critical vulnerability (CVE-2026-75574) arising from improper neutralization of template engine elements. The plugin incorrectly renders user-controlled input from the 'header.form.process.email.body' parameter as unsandboxed Twig templates. An authenticated user possessing 'api.access' and 'api.pages.write' permissions can leverage this flaw to inject arbitrary Twig expressions. When the affected page is processed, the server executes these expressions, leading to command injection and remote code execution (RCE) with the privileges of the underlying web server process. This vulnerability is particularly dangerous in environments where untrusted users are granted administrative or content-authoring roles within the Grav CMS.

## Attack Chain

1. Attacker authenticates to the target Grav CMS instance with 'api.access' and 'api.pages.write' privileges.
2. Attacker creates or edits a page configuration to define a form object.
3. Attacker embeds a malicious Twig expression payload within the 'header.form.process.email.body' field.
4. Attacker publishes the crafted page to the Grav site.
5. Attacker triggers the form processing logic by submitting the specific page form via a web browser or API client.
6. The Grav Email plugin parses the user-controlled 'email.body' header.
7. The Twig engine processes the unsandboxed template, executing the attacker-supplied command.
8. The web server process executes the arbitrary OS command, leading to full system compromise.

## Impact

Successful exploitation leads to full remote code execution on the server hosting the Grav CMS. An attacker can gain control over the web server, allowing for unauthorized access to sensitive application data, site defacement, or lateral movement within the hosting network. The vulnerability impacts all installations running Grav Email plugin versions prior to 4.2.2.

## Recommendation

Prioritize the immediate update of the Grav Email plugin to version 4.2.2 or later to mitigate CVE-2026-75574. Audit existing Grav CMS user accounts to identify and restrict users with 'api.access' and 'api.pages.write' permissions to minimize the attack surface. Deploy web application firewall (WAF) rules to inspect form submissions for suspicious Twig syntax and patterns consistent with template injection.

## Rules

title: "Detect Grav Email Plugin Twig Injection Attempt"
description: "Detects potential CVE-2026-75574 exploitation where Twig template syntax is injected into form parameters"
logsource:
 category: webserver
detection:
 selection:
 cs-uri-stem|contains: "/api/pages"
 cs-method: "POST"
 cs-uri-query|contains:
 - "{{"
 - "{%"
 - "_self"
 - "system("
 - "exec("
 condition: selection
level: high
tags:
 - attack.execution
 - attack.t1059.003
falsepositives:
 - "Legitimate administrative use of Twig templates in page headers"
tests:
 positive:
 - name: "Twig injection attempt in POST body"
 data:
 - cs-uri-stem: "/api/pages/save"
 cs-method: "POST"
 cs-uri-query: "body={{system('id')}}"
 negative:
 - name: "Standard page update"
 data:
 - cs-uri-stem: "/api/pages/save"
 cs-method: "POST"
 cs-uri-query: "body=contact_form"
handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "webserver access logs"
 event_or_channel: "HTTP request logging"
 required_fields:
 - "cs-uri-stem"
 - "cs-method"
 - "cs-uri-query"
 availability: "available"
 notes: "Requires logging of POST request bodies or query parameters"
 validation:
 status: "needs_environment_validation"
 steps:
 - "Attempt to save a page with a non-malicious Twig expression in a lab environment"
 expected_telemetry: "Web server access log entry showing the POST request"
 pass_criteria: "Rule matches the injected payload"
 known_evasions:
 - "Payload obfuscation using encoding"
 limitations:
 - "Does not detect successful execution, only injection attempts"
 tuning:
 - source: "Administrator activities"
 guidance: "Exclude known administrative IP ranges or service accounts"
 portability_notes:
 - platform: "Splunk/Elastic"
 note: "Requires extraction of POST body parameters into searchable fields"
 suggested_owner: "Detection Engineering"
