---
title: MantisBT Stored XSS Vulnerability via Tag Timeline Display
slug: 2024-01-03-mantisbt-xss
description: A stored HTML injection vulnerability (CVE-2026-33548) exists in MantisBT version 2.28.0, allowing attackers to inject HTML and execute arbitrary JavaScript by manipulating tag names displayed in the timeline due to improper escaping.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mantisbt
  - xss
  - html-injection
  - cve-2026-33548
  - webserver
vendors:
  - MantisBT
products:
  - MantisBT
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-73vx-49mv-v8w5
rules:
  - title: MantisBT Tag Based XSS Attempt
    description: Detects potential XSS attempts in MantisBT by identifying suspicious HTML tags within tag names in requests to my_view_page.php.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: MantisBT Suspicious Tag
    description: Detects potential creation of suspicious tags with HTML entities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability has been identified in MantisBT version 2.28.0. This flaw, tracked as CVE-2026-33548, stems from the improper handling of tag names retrieved from the history when displaying them in the timeline (my_view_page.php). Specifically, the application fails to adequately escape HTML entities within the tag names, allowing an attacker to inject malicious HTML code. If Content Security Policy (CSP) settings are permissive, this injected HTML can be leveraged to execute arbitrary JavaScript code within the context of a user's browser. This can lead to session hijacking, defacement, or other malicious activities. The vulnerability was discovered and responsibly reported by Vishal Shukla. Defenders should upgrade or implement workarounds.

## Attack Chain

1. An attacker with appropriate privileges logs into a vulnerable MantisBT instance.
2. The attacker creates a new tag with a malicious payload embedded in the tag name (e.g., `<img src=x onerror=alert(1)>`).
3. The attacker associates the malicious tag with an issue.
4. The attacker renames the malicious tag, further storing the payload in the history.
5. A user views the issue's timeline on `my_view_page.php`.
6. The application retrieves the tag name from the history without proper escaping.
7. The malicious HTML is rendered in the user's browser.
8. If CSP allows, the injected JavaScript executes, leading to XSS.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of other MantisBT users' browsers. This can lead to sensitive information disclosure, such as session cookies, which can then be used to hijack user accounts. The impact could also include defacement of the MantisBT interface or redirection of users to malicious websites. The vulnerability affects MantisBT 2.28.0 and requires immediate patching or mitigation.

## Recommendation

*   Upgrade to a patched version of MantisBT that includes the fix f32787c14d4518476fe7f05f992dbfe6eaccd815.
*   Apply the suggested workaround by wrapping `$this->tag_name` in a `string_html_specialchars()` call in `IssueTagTimelineEvent::html()`.
*   Deploy the Sigma rule "MantisBT Tag Based XSS Attempt" to detect potential exploitation attempts within web server logs.
*   Monitor web server logs for requests to `my_view_page.php` containing suspicious tag names with HTML entities as detected by the Sigma rule "MantisBT Suspicious Tag".
