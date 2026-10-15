---
title: Reflected XSS Vulnerability in Vitess vttablet twopczHandler
slug: 2026-10-vitess-xss
description: An unauthenticated reflected XSS vulnerability (CVE-2026-104252) in the Vitess vttablet twopczHandler allows attackers to execute arbitrary JavaScript in the context of an operator's session, potentially exposing sensitive debug information.
date: "2026-10-15T22:23:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vitess:vitess:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - vitess
  - cve-2026-104252
vendors:
  - Vitess
products:
  - vttablet (< 0.23.5, >= 0.24.0, < 0.24.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The endpoint is reachable by anyone who can hit the vttablet's HTTP port.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: A crafted Action or dtid value yields a reflected XSS that executes in the operator's browser.
    confidence_band: high
cves:
  - id: CVE-2026-104252
    cvss: 9.8
    epss: 0.00885
references:
  - https://github.com/advisories/GHSA-v75v-6fpf-gvw8
rules:
  - title: Detect CVE-2026-104252 Exploitation - XSS Attempt in vttablet twopczHandler
    description: Detects exploitation attempts against CVE-2026-104252 by identifying suspicious script-related strings in the Action or dtid parameters of the /twopcz endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict access to vttablet HTTP port 15999 to trusted management networks only.
      owner: SOC
      due: 24h
      evidence: Mitigation step 1 in source.
  mitigation_plan:
    - priority: immediate
      action: Firewall vttablet HTTP port 15999 from public or untrusted network exposure.
      owner: IT Operations
      addresses: CVE-2026-104252
      evidence: Source workaround documentation.
---

The Vitess `vttablet` component is vulnerable to reflected Cross-Site Scripting (XSS) due to improper input sanitization in the `twopczHandler` located in `go/vt/vttablet/tabletserver/twopcz.go`. The handler incorrectly reflects user-controlled `Action` and `dtid` form values directly into the HTML response body without HTML escaping. Because the endpoint serves responses as `text/html` and utilizes an 'allow-all' default access control policy, unauthenticated attackers can trigger this vulnerability by tricking an authenticated operator into visiting a specially crafted URL. 

Successful exploitation allows for the execution of arbitrary JavaScript within the operator's browser session. Given the same-origin nature of the attack, the script can access sensitive unauthenticated debug endpoints such as `/queryz`, `/querylogz`, `/debug/env`, and `/debug/vars`, which may contain query plans, transactional data, MySQL credentials, and topology information. The vulnerability affects all released versions of Vitess prior to the inclusion of the fix (merged into the `main` branch on 2026-06-09).

## Impact

The vulnerability is categorized as high severity (CVSS 7.7) because it allows for the exfiltration of sensitive configuration data and database credentials. While the vulnerability does not directly disrupt service, the exposure of environment variables via `/debug/env` could lead to full database compromise or secondary service disruptions if credentials are rotated or exploited offline.

## Recommendation

- Implement network-level restrictions to ensure the vttablet HTTP port (default 15999) is not exposed to untrusted networks or the public internet.
- Override the default Vitess 'allow-all' ACL policy to require authentication for debug endpoints and the `/twopcz` handler.
- Deploy a web application firewall (WAF) or reverse proxy in front of vttablet instances to sanitize incoming requests and block URLs containing suspicious patterns associated with XSS payloads (e.g., `<script>`, `onerror`, `onload`).
- Prioritize upgrading Vitess once patch releases addressing CVE-2026-104252 are available for your respective version branch.
