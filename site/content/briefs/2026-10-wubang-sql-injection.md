---
title: Remote SQL Injection in Wubang Five-in-One Safety Production Management System
slug: 2026-10-wubang-sql-injection
description: An unauthenticated remote SQL injection vulnerability in the xp_cmdshell function of the /ws.asmx endpoint in Wubang Five-in-One Safety Production Management Information System allows for arbitrary command execution.
date: "2026-10-19T20:11:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wuxi_wubang_security_software:wubang_five_in_one_safety_production_management_information_system:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - rce
  - vulnerability
  - industrial
vendors:
  - Wuxi Wubang Security Software
products:
  - Wubang Five-in-One Safety Production Management Information System (<= 3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Affected is the function xp_cmdshell of the file /ws.asmx.
    confidence_band: high
cves:
  - id: CVE-2026-112252
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112252
rules:
  - title: Detect CVE-2026-112252 Exploitation Attempt - SQL Injection in /ws.asmx
    description: Detects potential SQL injection attempts targeting the sql parameter within the /ws.asmx web service endpoint.
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
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the /ws.asmx endpoint
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote SQL injection and RCE
  enrichment_needed:
    - item: CVE-2026-112252
      owner: CTI
      reason: Monitor for any public exploit scripts that may emerge
      evidence: The exploit has been disclosed to the public and may be used.
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable systems from external network access
      owner: IT Operations
      addresses: CVE-2026-112252
      evidence: No vendor patch available
---

A critical SQL injection vulnerability, tracked as CVE-2026-112252, affects the Wuxi Wubang Security Software Wubang Five-in-One Safety Production Management Information System in versions up to 3.5. The vulnerability resides within the xp_cmdshell function accessible via the /ws.asmx web service endpoint. An unauthenticated remote attacker can supply malicious input to the sql argument, leading to SQL injection. Because the application interacts with system-level functions, this vulnerability can be leveraged to execute arbitrary commands on the underlying host. The vulnerability has been disclosed publicly, and given the lack of vendor response or remediation, affected systems are at high risk of compromise.

## Impact

Successful exploitation allows for remote code execution with the privileges of the web service process. This can lead to full system compromise, data exfiltration, or the installation of persistent backdoors on the affected industrial safety management infrastructure.

## Recommendation

- Monitor web server logs for suspicious requests to /ws.asmx containing SQL keywords or command execution characters in the 'sql' parameter.
- Implement network segmentation to isolate the Management Information System from external and untrusted networks.
- If the application cannot be patched, consider restricting access to the /ws.asmx endpoint using a Web Application Firewall (WAF) or equivalent gateway controls.
- Audit the service account permissions under which the Wubang system runs to adhere to the principle of least privilege.
