---
title: CrushFTP Authentication Bypass Exploitation
slug: 2026-09-crushftp-auth-bypass
description: CVE-2025-31161 in CrushFTP is being exploited to gain unauthorized access and execute malicious commands, with activity linked to Hellcat ransomware operations.
date: "2026-09-21T19:13:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*
tags:
  - web
  - ransomware
  - vulnerability
vendors:
  - CrushFTP
products:
  - CrushFTP (< 10.8.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The following analytic detects potential exploitation of the CrushFTP authentication bypass vulnerability (CVE-2025-31161).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: This detection identifies suspicious command execution patterns associated with exploitation of this vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: This detection identifies suspicious command execution patterns associated with exploitation of this vulnerability.
    confidence_band: high
cves:
  - id: CVE-2025-31161
    cvss: 9.8
    epss: 0.99976
references:
  - https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation
  - https://nvd.nist.gov/vuln/detail/CVE-2025-31161
  - https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update
rules:
  - title: Detect CVE-2025-31161 Exploitation via CrushFTP Logs
    description: Detects exploitation of CVE-2025-31161 by identifying suspicious commands in CrushFTP server logs, including mesch.exe and specific execution arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
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
    - action: Patch CrushFTP to 10.8.4 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2025-31161 is a known critical authentication bypass vulnerability
  hunt_leads:
    - lead: Search logs for 'mesch.exe', 'b64exec', 'fullinstall', or 'run' in CrushFTP logs
      technique_id: T1190
      data_needed:
        - CrushFTP application logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic detects these strings in association with CVE-2025-31161
  mitigation_plan:
    - priority: immediate
      action: Upgrade CrushFTP to 10.8.4 or later
      owner: IT Operations
      addresses: CVE-2025-31161
      evidence: CrushFTP security updates
---

CVE-2025-31161 is a critical authentication bypass vulnerability in CrushFTP that allows unauthenticated remote attackers to gain unauthorized access to the application. Once the authentication mechanism is bypassed, attackers perform post-exploitation activities by executing system-level commands through the application's interface. Observed malicious activity includes the invocation of binaries like 'mesch.exe' or specific command arguments such as 'b64exec', 'fullinstall', or 'run'. This vulnerability has been actively exploited in the wild and linked to the Hellcat ransomware campaign. Defenders should monitor CrushFTP server logs for evidence of these specific command patterns, as they signify successful unauthorized access and subsequent execution of attacker-controlled code on the underlying host.

## Attack Chain

1. Attacker sends a specially crafted HTTP request to the CrushFTP server to bypass authentication (CVE-2025-31161).
2. The application processes the request, allowing the attacker to reach restricted administrative or system-level endpoints.
3. Attacker uses the established session to execute arbitrary commands through the CrushFTP command interface.
4. Command execution triggers the launch of 'mesch.exe' or executes arguments like 'b64exec' or 'fullinstall'.
5. The server process spawns the requested commands, which may include further script execution or malware deployment.
6. Attacker gains persistence or performs reconnaissance on the system.
7. Attacker proceeds to stage and execute the final payload, such as Hellcat ransomware, for exfiltration and extortion.

## Impact

Successful exploitation allows remote attackers to bypass authentication and execute code with the privileges of the CrushFTP service. This can lead to total system compromise, data theft, and the deployment of ransomware. The vulnerability has been explicitly linked to Hellcat ransomware campaigns, which target organizations using CrushFTP for file transfer services.

## Recommendation

1. Patch CrushFTP immediately by upgrading to the version that remediates CVE-2025-31161.
2. Enable ingestion of CrushFTP logs into your SIEM and deploy the detection rules below to identify exploitation attempts.
3. Review all CrushFTP server activity for the command patterns 'mesch.exe', 'b64exec', 'fullinstall', or 'run' in process or execution logs.
4. Isolate internet-facing CrushFTP servers or apply strict access controls to limit exposure to these services.
5. Investigate any instances where unauthorized users or suspicious IPs are observed executing system commands via the CrushFTP interface.
