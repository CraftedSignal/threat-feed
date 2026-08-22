---
title: Stored XSS in YOURLS via Referer Header
slug: 2026-08-yourls-xss
description: The YOURLS URL shortener is vulnerable to stored cross-site scripting (XSS) via the Referer header, allowing unauthenticated attackers to execute arbitrary JavaScript in an administrator's browser context.
date: "2026-08-22T01:17:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - stored-xss
  - cve-2026-63135
products:
  - YOURLS (>= 1.5.1, <= 1.10.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can send a crafted Referer header to any existing short URL.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The malicious payload is embedded into Google Charts JavaScript without JavaScript-string escaping, causing stored cross-site scripting.
    confidence_band: high
cves:
  - id: CVE-2026-63135
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-5h77-88j3-r659
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-63135
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade YOURLS to a version containing the fix for CVE-2026-63135.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends updating to patched versions.
  mitigation_plan:
    - priority: immediate
      action: Review administrative logs and audit short-link configurations for unauthorized changes.
      owner: Security Operations
      addresses: CVE-2026-63135
      evidence: Stored XSS can be used to modify links and steal API tokens.
---

YOURLS versions 1.5.1 through 1.10.3 are vulnerable to stored cross-site scripting (XSS) resulting from improper sanitization of the HTTP 'Referer' header. An unauthenticated attacker can supply a malicious 'Referer' header to a short URL, which is subsequently logged by the application. When an administrator or authorized user views the statistics page for that short URL, the malicious payload is embedded into Google Charts JavaScript without proper escaping of string metacharacters. This vulnerability is reachable in default private installations when statistics are viewed by an authenticated user, as well as in installations with the 'YOURLS_PRIVATE_INFOS' configuration set to 'false'. Successful exploitation allows for the execution of arbitrary JavaScript within the origin of the YOURLS administration panel, potentially leading to unauthorized administrative actions and sensitive information disclosure.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP request containing a malicious 'Referer' header (e.g., "http://x',1],['marker',alert(1)],['z.tld/path").
2. The attacker triggers a request for an existing short URL on the target YOURLS instance using the crafted 'Referer' header.
3. The `yourls_log_redirect` function processes the request and stores the unsanitized (but truncated) 'Referer' header in the application's database.
4. An authenticated administrator navigates to the statistics page (e.g., `<keyword>+`) for the targeted short URL.
5. The application extracts the domain from the logged referrers and passes it to `yourls_stats_pie`.
6. The `yourls_google_array_to_data_table` function concatenates the malicious referrer domain directly into the Google Charts JavaScript array without sanitization.
7. The administrator's browser executes the injected JavaScript payload within the session context.
8. The attacker uses the privileged session to perform actions such as creating/deleting links, modifying destinations, or stealing API tokens.

## Impact

Successful exploitation results in arbitrary JavaScript execution within the authenticated session of a YOURLS administrator. An attacker can use this access to perform privileged actions, including modifying or deleting existing short-link destinations to facilitate phishing or malware distribution, and accessing sensitive administrative tools. Furthermore, the XSS can be used to extract the administrative API signature token from `/admin/tools.php`, allowing for persistent, passwordless API access to the YOURLS instance until the secret is rotated.

## Recommendation

Prioritize upgrading all YOURLS instances to a patched version that correctly escapes JavaScript string metacharacters in the statistics generation logic. Until an upgrade can be performed, monitor web server logs for suspicious 'Referer' headers containing characters indicative of XSS attempts, such as single quotes, square brackets, or parentheses. If logs reveal evidence of attempted exploitation, rotate administrative API tokens immediately and audit the current short-link inventory for unauthorized modifications.
