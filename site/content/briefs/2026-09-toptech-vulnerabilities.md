---
title: Critical Vulnerabilities in Toptech TMS7 and TopHAT
slug: 2026-09-toptech-vulnerabilities
description: Multiple critical vulnerabilities in Toptech TMS7 and TopHAT version 7.6.3 enable unauthenticated attackers to execute arbitrary code, manipulate databases via SQL injection, and gain unauthorized access to sensitive system files.
date: "2026-09-29T16:25:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ics
  - cve
  - web-application-vulnerability
vendors:
  - Toptech Systems
products:
  - TMS7 (7.6.3)
  - TopHAT (7.6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The file export endpoint allows any unauthenticated attacker to export arbitrary database tables by sending a crafted POST request.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: PHP'
    evidence: The TMS file upload endpoint fails to enforce server-side file type restrictions, allowing an attacker to upload and execute arbitrary PHP files on the web server.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-02
  - https://www.toptech.com/blog/tms7-version-7-8-strengthens-security
  - https://www.cve.org/CVERecord?id=CVE-2026-71379
  - https://www.cve.org/CVERecord?id=CVE-2026-70356
  - https://www.cve.org/CVERecord?id=CVE-2026-72510
  - https://www.cve.org/CVERecord?id=CVE-2026-63713
  - https://www.cve.org/CVERecord?id=CVE-2026-68954
  - https://www.cve.org/CVERecord?id=CVE-2026-68068
  - https://www.cve.org/CVERecord?id=CVE-2026-72507
  - https://www.cve.org/CVERecord?id=CVE-2026-71302
  - https://www.cve.org/CVERecord?id=CVE-2026-69662
  - https://www.cve.org/CVERecord?id=CVE-2026-71189
rules:
  - title: Detects Potential CVE-2026-70356 Exploitation - Arbitrary PHP File Upload
    description: Detects unauthorized attempts to upload PHP files via the TMS file upload endpoint.
    platform: sigma
    severity: critical
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
    - SOC
  immediate_actions:
    - action: Upgrade Toptech TMS7 and TopHAT to version 7.8 or later
      owner: IT Operations
      due: 24h
      evidence: Mitigation section of the CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 7.8
      owner: IT Operations
      addresses: All CVEs listed
      evidence: Vendor mitigation advisory
---

Toptech Systems has disclosed multiple critical vulnerabilities affecting TMS7 and TopHAT version 7.6.3, utilized widely within the energy, chemical, and transportation sectors. These vulnerabilities range from unauthenticated file and directory access to unrestricted file uploads, SQL injection, session fixation, and cross-site scripting. The most severe flaw, CVE-2026-71379, allows unauthenticated attackers to export arbitrary database tables via crafted POST requests, while CVE-2026-70356 permits the upload and execution of arbitrary PHP files on the web server. Given the nature of these systems in industrial environments, successful exploitation could lead to full system compromise, data exfiltration, and disruption of critical infrastructure operations. Users are required to upgrade to version 7.8 or later immediately to address these flaws.

## Impact

The vulnerabilities pose a severe risk to critical infrastructure sectors, including energy, chemical, and transportation systems worldwide. Successful exploitation allows for unauthenticated arbitrary code execution, database compromise via SQL injection, and access to sensitive file systems, potentially resulting in operational downtime or the exposure of sensitive industrial control data.

## Recommendation

* Upgrade Toptech TMS7 and TopHAT to release 7.8 or later immediately as specified in the Toptech Systems security advisory.
* Inspect web application logs for anomalous POST requests to file export and upload endpoints, particularly those containing suspicious file extensions or SQL syntax.
* Enforce strict access control lists for internet-facing interfaces to limit the exposure of management consoles for TMS7 and TopHAT.
* Monitor for unauthorized creation of new files within the web server directories, specifically looking for unexpected PHP files.
