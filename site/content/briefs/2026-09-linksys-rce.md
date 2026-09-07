---
title: OS Command Injection in Linksys RE7000 Range Extender
slug: 2026-09-linksys-rce
description: An OS command injection vulnerability (CVE-2026-86299) in the Linksys RE7000 version 2.0.15 allows unauthenticated remote code execution via the PingTest Handler component.
date: "2026-09-07T12:52:51Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:linksys:re7000_firmware:2.0.15:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-security
vendors:
  - Linksys
products:
  - RE7000 (2.0.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument pingTestIp/pingTestPktSize/pingTestTimes results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-86299
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86299
rules:
  - title: Detects CVE-2026-86299 Exploitation - Command Injection in PingTest Handler
    description: Detects exploitation attempts against CVE-2026-86299 by identifying shell metacharacters in the query parameters of requests to the PingTest CGI endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to web server or WAF logs to detect exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Exploit is public and may be used.
  mitigation_plan:
    - priority: immediate
      action: Restrict remote access to the range extender management interface or apply firmware updates if released by Linksys.
      owner: IT Operations
      addresses: CVE-2026-86299
      evidence: Vulnerability affects RE7000 2.0.15
---

CVE-2026-86299 describes a critical remote OS command injection vulnerability discovered in the Linksys RE7000 Wi-Fi range extender, specifically in firmware version 2.0.15. The vulnerability resides within the PingTest Handler component, managed by the platform_event_pingTest function in the /cgi-bin/json.cgi?PingTest endpoint. An attacker can supply malicious input via the pingTestIp, pingTestPktSize, or pingTestTimes arguments to execute arbitrary system commands with elevated privileges. Because the device is an internet-facing network component, this flaw presents a significant risk for unauthorized system access and device takeover. Public exploit material is currently available, increasing the likelihood of active exploitation. Defenders should monitor network traffic for anomalous POST or GET requests to the identified CGI binary and prioritize patching or isolating vulnerable devices.

## Impact

Successful exploitation allows for full remote code execution on the affected Linksys RE7000 range extender. This enables attackers to gain administrative control over the networking hardware, potentially facilitating traffic interception, internal network reconnaissance, or pivoting into the local area network (LAN). As a consumer networking device, this impacts the integrity and availability of home and small office network infrastructure.

## Recommendation

* Immediately isolate vulnerable Linksys RE7000 devices (firmware 2.0.15) from the public internet if a firmware update is not yet available or has not been applied.
* Monitor network traffic for HTTP requests targeting /cgi-bin/json.cgi?PingTest that contain shell metacharacters such as ';', '|', '&&', or '`' within the pingTestIp, pingTestPktSize, or pingTestTimes parameters.
* Deploy firewall rules to block access to the management interface of networking devices from non-trusted or internet-facing networks.
