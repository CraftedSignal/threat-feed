---
title: Local File Inclusion Vulnerability in Eventin WordPress Plugin
slug: 2026-09-eventin-lfi
description: The Eventin plugin for WordPress contains an LFI vulnerability allowing authenticated attackers with custom-level access to execute arbitrary PHP files on the server.
date: "2026-09-09T03:51:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:eventin_event_calendar_event_registration_tickets_booking:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - lfi
  - cve-2026-15406
vendors:
  - WordPress
products:
  - Eventin – Event Calendar, Event Registration, Tickets & Booking (AI Powered) (<= 4.1.22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Eventin – Event Calendar, Event Registration, Tickets & Booking (AI Powered) plugin for WordPress is vulnerable to Local File Inclusion
    confidence_band: high
cves:
  - id: CVE-2026-15406
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15406
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update Eventin plugin to version 4.1.23 or later
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable <= 4.1.22
---

The Eventin - Event Calendar, Event Registration, Tickets & Booking (AI Powered) plugin for WordPress is vulnerable to Local File Inclusion (LFI) in all versions up to and including 4.1.22. The vulnerability exists due to improper validation of the 'event_layout' parameter within the plugin's code. An authenticated attacker with custom-level access or higher can manipulate this parameter to point to arbitrary files on the web server. By chaining this with an ability to upload files or referencing existing sensitive files, an attacker can trigger the execution of arbitrary PHP code. This vulnerability poses a significant risk to site integrity and confidentiality, as it facilitates unauthorized access to server-side logic and sensitive configuration data.

## Attack Chain

1. Attacker obtains authenticated access to the WordPress site with at least 'custom-level' permissions.
2. Attacker identifies the target URL utilizing the Eventin plugin that processes the 'event_layout' parameter.
3. Attacker identifies a mechanism to place a malicious PHP file on the server (e.g., via media uploads, theme editing, or other vulnerable plugins).
4. Attacker crafts a malicious HTTP GET or POST request targeting the vulnerable parameter.
5. The attacker sets the 'event_layout' parameter to the file path of the malicious PHP file previously uploaded.
6. The web server process includes the specified file and executes the embedded PHP code.
7. Attacker achieves remote code execution in the context of the web server user.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the web server, leading to potential full site compromise. This may include sensitive data theft, the installation of persistent backdoors, or the lateral movement into the hosting infrastructure.

## Recommendation

Prioritize updating the Eventin - Event Calendar, Event Registration, Tickets & Booking (AI Powered) plugin to the version containing the security fix immediately. If immediate patching is not possible, restrict access to the dashboard for non-administrative roles to mitigate the authentication requirement. Monitor web server logs for unexpected patterns in the 'event_layout' parameter containing directory traversal sequences or references to non-standard PHP files.

## Rules

title: "Detect Local File Inclusion Attempt via Eventin Plugin"
description: "Detects exploitation attempts of CVE-2026-15406 where the 'event_layout' parameter is used to include arbitrary files."
logsource:
 category: webserver
detection:
 selection:
 cs-uri-query|contains: "event_layout="
 cs-uri-query|contains:
 - "../"
 - "..\\"
 - ".php"
 condition: selection
level: high
tags:
 - attack.initial_access
 - attack.t1190
falsepositives:
 - "Legitimate use of the parameter by specific complex themes that might include localized partials; verify plugin documentation"
tests:
 positive:
 - name: "LFI attempt via event_layout"
 data:
 - cs-uri-query: "event_layout=../../../wp-config.php"
 negative:
 - name: "Normal plugin usage"
 data:
 - cs-uri-query: "event_layout=default-grid"
handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Web server access logs"
 event_or_channel: "HTTP requests"
 required_fields:
 - "cs-uri-query"
 availability: "available"
 notes: "Ensure web server logs include full request query strings."
 validation:
 status: "needs_environment_validation"
 steps:
 - "Verify that requests to the plugin path are logged with the full query string"
 expected_telemetry: "Web server logs matching the detection pattern"
 pass_criteria: "Alert triggers on malicious path traversal attempt"
 known_evasions:
 - "URL encoding of malicious characters"
 limitations:
 - "Does not detect if the payload is submitted via POST body if the log source only records URI query"
 tuning:
 - source: "Web traffic"
 guidance: "Review log samples to ensure the event_layout value is not legitimately dynamic"
 portability_notes:
 - platform: "Splunk|Elastic"
 note: "Ensure field normalization for HTTP query parameters"
 suggested_owner: "Detection Engineering"
