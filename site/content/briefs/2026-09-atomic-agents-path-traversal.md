---
title: Path Traversal Vulnerability in atomic-agents-stack
slug: 2026-09-atomic-agents-path-traversal
description: The atomic-agents-stack library before version 1.1.0 is vulnerable to path traversal within its dashboard HTTP server, allowing remote attackers to read arbitrary files via crafted requests.
date: "2026-09-15T17:44:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:atomic-agents-stack:atomic-agents-stack:*:*:*:*:*:*:*:*
products:
  - atomic-agents-stack (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The dashboard HTTP server allows remote attackers to read arbitrary files by supplying directory traversal sequences in request paths.
    confidence_band: high
cves:
  - id: CVE-2026-91989
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91989
rules:
  - title: Detect CVE-2026-91989 Exploitation - Path Traversal in atomic-agents-stack
    description: Detects path traversal attempts targeting the dashboard component by looking for directory traversal sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade atomic-agents-stack to 1.1.0
      owner: IT Operations
      due: 24h
      evidence: Source states fixed version is 1.1.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.1.0
      owner: IT Operations
      addresses: CVE-2026-91989
      evidence: NVD advisory
---

The atomic-agents-stack library, specifically versions prior to 1.1.0, contains a critical path traversal vulnerability within its dashboard HTTP server component. This vulnerability stems from improper input validation in the DashboardHandler.do_GET endpoint. Remote, unauthenticated attackers can leverage this flaw by supplying directory traversal sequences, such as "../", within the HTTP request path. By doing so, the attacker can bypass existing path containment checks designed to restrict access to the agents_root directory, effectively granting them the ability to read arbitrary files from the underlying filesystem where the application is hosted. This vulnerability poses a significant risk to the confidentiality of sensitive configuration files, environment variables, or other stored data accessible to the service process. Defenders should prioritize updating to version 1.1.0 or later to mitigate this exposure.

## Impact

Successful exploitation of CVE-2026-91989 allows an attacker to read any file on the server accessible to the atomic-agents-stack process. This can lead to full disclosure of application secrets, environment configurations, and other sensitive host data. The vulnerability is highly impactful due to the ease of exploitation, requiring only unauthenticated HTTP requests to the dashboard interface.

## Recommendation

- Upgrade the atomic-agents-stack dependency to version 1.1.0 or later immediately.
- Review web server access logs for requests containing suspicious path segments like "../" or "%2e%2e/" targeting dashboard endpoints.
- Apply WAF rules to block HTTP requests containing directory traversal sequences directed at paths mapped to the dashboard component.
