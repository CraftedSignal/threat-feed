---
title: Fortinet FortiClient EMS Unauthenticated Remote Code Execution via CVE-2026-35616
slug: 2026-04-forticlient-ems-rce
description: A critical vulnerability, CVE-2026-35616, exists in Fortinet FortiClient EMS (Endpoint Management Server) allowing unauthenticated attackers to bypass API authentication and authorization checks to execute arbitrary code or commands, potentially leading to full compromise of the EMS infrastructure.
date: "2026-04-07T15:08:28Z"
severities:
  - critical
exploited: true
type: threat
types:
  - threat
tags:
  - fortinet
  - forticlient
  - ems
  - rce
  - cve-2026-35616
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35616
    cvss: 9.8
    epss: 0.41371
references:
  - https://ccb.belgium.be/advisories/warning-critical-cve-2026-35616-actively-exploited-allowing-attackers-gain-unauthorized
  - https://fortiguard.fortinet.com/psirt/FG-IR-26-099
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35616
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-35616
rules:
  - title: Detect Unauthorized API Access to FortiClient EMS
    description: Detects suspicious HTTP requests indicative of unauthorized API access attempts to FortiClient EMS, potentially exploiting CVE-2026-35616.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Code Execution via FortiClient EMS API
    description: Detects potential code execution attempts via crafted HTTP requests to the FortiClient EMS API, indicative of CVE-2026-35616 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-35616, has been identified in Fortinet FortiClient EMS versions 7.4.5 through 7.4.6. This vulnerability allows unauthenticated attackers to bypass API authentication and authorization checks, enabling them to execute arbitrary code or commands on the EMS server. FortiClient EMS is a centralized platform used to deploy, configure, and monitor FortiClient agents across an organization, making it a high-value target. The vulnerability is being actively exploited in the wild. Successful exploitation can lead to full compromise of the EMS infrastructure, impacting all managed endpoints and potentially enabling lateral movement across enterprise networks. Defenders should prioritize patching and enhance monitoring capabilities.

## Attack Chain

1. The attacker identifies a vulnerable FortiClient EMS instance (versions 7.4.5 through 7.4.6) exposed on the network.
2. The attacker crafts a malicious HTTP/API request targeting the unauthenticated API interface of the FortiClient EMS.
3. The crafted request bypasses authentication and authorization checks due to improper access control (CWE-284).
4. The bypassed access controls allow the attacker to execute unauthorized code or commands on the EMS server.
5. The attacker obtains control of administrative functionality on the FortiClient EMS server.
6. The attacker manipulates or exfiltrates sensitive configuration and policy data stored on the EMS.
7. The attacker deploys malicious payloads to managed endpoints via the compromised EMS server.
8. The attacker uses the compromised EMS as a foothold for further network intrusion or lateral movement.

## Impact

Successful exploitation of CVE-2026-35616 can lead to a full compromise of the FortiClient EMS infrastructure. This includes the ability to manipulate or exfiltrate sensitive configuration and policy data, corrupt or disable endpoint protections, disrupt endpoint management services, and deploy malicious payloads to managed endpoints. The vulnerability enables lateral movement across enterprise networks. The CCB has confirmed that this vulnerability has been exploited in the wild.

## Recommendation

*   Apply the latest Fortinet patch for FortiClient EMS to remediate CVE-2026-35616 immediately.
*   Upscale monitoring and detection capabilities to identify any related suspicious activity, ensuring a swift response in case of an intrusion as recommended by the CCB.
*   Deploy the Sigma rule detecting unauthorized API access to the FortiClient EMS webserver to your SIEM and tune for your environment.
