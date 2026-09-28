---
title: Remote Command Injection in Netcore NR289-GE
slug: 2026-09-netcore-cve
description: Netcore NR289-GE version 1.4.5102 is vulnerable to remote unauthenticated OS command injection via the ip argument in the /ap_ip.cgi component.
date: "2026-09-28T16:20:14Z"
lastmod: "2026-09-28T16:20:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:netcore:nr289_ge:*:*:*:*:*:*:*:*
tags:
  - cve
  - remote-code-execution
  - network-device
  - edge-security
vendors:
  - Netcore
products:
  - NR289-GE (1.4.5102)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attack can be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument mac leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-101072
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101072
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101075
rules:
  - title: Detects CVE-2026-101072 Exploitation - OS Command Injection via /ap_ip.cgi
    description: Detects exploitation attempts against Netcore NR289-GE where the ip argument contains common shell injection characters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detects CVE-2026-101075 Exploitation - OS Command Injection via /location_time.cgi
    description: Detects exploitation attempts against CVE-2026-101075 by identifying shell metacharacters in the mac parameter of the /location_time.cgi endpoint
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Security
  immediate_actions:
    - action: Restrict access to /ap_ip.cgi on Netcore NR289-GE devices via ACLs
      owner: Network Security
      due: 24h
      evidence: Critical vulnerability with public exploit
  hunt_leads:
    - lead: Search logs for requests to /ap_ip.cgi containing shell metacharacters
      technique_id: T1203
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit targets /ap_ip.cgi via ip argument
  mitigation_plan:
    - priority: immediate
      action: Disable external access to web management interface
      owner: Network Security
      addresses: CVE-2026-101072
      evidence: Publicly available exploit
updates:
  - at: "2026-09-28T16:20:31Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-101075 Exploitation - OS Command Injection via /location_time.cgi'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101075
---

A critical security vulnerability has been identified in the Netcore NR289-GE router, specifically in version 1.4.5102. The flaw resides within the CGI handler component, specifically the /ap_ip.cgi script. An unauthenticated remote attacker can inject arbitrary operating system commands by manipulating the 'ip' HTTP GET or POST parameter. Because the CGI handler processes this input without sufficient sanitization before passing it to a system shell, the vulnerability allows for full system compromise with the privileges of the web server process. The vendor has not responded to disclosure attempts, and proof-of-concept exploit code is publicly available, increasing the risk of exploitation by opportunistic threat actors targeting edge devices.

## Impact

Successful exploitation of this vulnerability results in full remote control of the affected Netcore NR289-GE device. Potential impacts include unauthorized access to internal network traffic, lateral movement into the local network, and the deployment of persistent malware or backdoors on the gateway device. Given the critical 10.0 CVSS score, this vulnerability poses a severe risk to any organization utilizing these routers in internet-facing configurations.

## Recommendation

Deploy network-level detection for the suspicious HTTP requests associated with this exploit. Since the vendor has not provided a patch, administrators should prioritize restricting access to the web management interface of the NR289-GE to trusted IP ranges only. If remote management is not required, disable the web management interface entirely until a vendor-supplied firmware update becomes available.
