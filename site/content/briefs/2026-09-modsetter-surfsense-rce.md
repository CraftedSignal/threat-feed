---
title: Remote Command Injection in MODSetter SurfSense
slug: 2026-09-modsetter-surfsense-rce
description: MODSetter SurfSense up to version 2.0.3 is vulnerable to remote command injection via the MCP Connector Integration component, allowing unauthenticated attackers to execute arbitrary system commands.
date: "2026-09-29T04:24:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:modsetter:surfsense:*:*:*:*:*:*:*:*
vendors:
  - MODSetter
products:
  - SurfSense (<= 2.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Such manipulation leads to command injection. It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-102243
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102243
rules:
  - title: Detect CVE-2026-102243 Exploitation - Command Injection via MCP Connector
    description: Detects exploitation attempts against CVE-2026-102243 where an attacker sends a POST request with shell metacharacters to the vulnerable test endpoint.
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
    - action: Deploy the provided WAF/web-server rule for CVE-2026-102243
      owner: SOC
      due: 24h
      evidence: Source confirms public exploit availability
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the MCP Connector endpoint
      owner: IT Operations
      addresses: CVE-2026-102243
      evidence: Exploit is publicly available
---

A high-severity command injection vulnerability, identified as CVE-2026-102243, affects MODSetter SurfSense versions up to 2.0.3. The flaw resides within the MCP Connector Integration component, specifically within the /api/search-source/connectors/mcp/test endpoint. Remote attackers can leverage this unauthenticated endpoint to inject and execute arbitrary system commands on the underlying host. The vulnerability is confirmed to have publicly available exploit code, increasing the likelihood of exploitation. Despite early disclosure, the vendor has not provided a patch or formal response, leaving installations currently exposed. Defenders must prioritize restricting network access to the SurfSense application and monitoring for unusual process creation originating from the web server process.

## Impact

Successful exploitation leads to full remote code execution on the server hosting SurfSense. Given that the MCP Connector Integration typically operates with elevated privileges to perform system connectivity tasks, this allows attackers to gain persistence, exfiltrate sensitive data, or move laterally within the internal network. No specific victim counts are available, but any internet-facing instance of SurfSense is considered at critical risk.

## Recommendation

* Monitor web server logs for suspicious requests targeting /api/search-source/connectors/mcp/test containing shell metacharacters.
* Restrict network access to the SurfSense administration and integration endpoints to trusted internal IP addresses only.
* Implement egress filtering on the server to prevent the application from making unauthorized outbound connections often used by reverse shells.
* Since no patch is available, consider deploying a Web Application Firewall (WAF) rule to drop HTTP requests containing common shell command injection strings targeting this specific endpoint.
