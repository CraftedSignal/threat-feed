---
title: Remote OS Command Injection in Shibby Tomato
slug: 2026-08-shibby-tomato-rce
description: Shibby Tomato version 1.28.0000 is vulnerable to remote OS command injection via the wan_iface parameter in the new_qoslimit_stop function, allowing unauthenticated or authenticated administrative attackers to execute arbitrary code.
date: "2026-08-06T11:23:13Z"
lastmod: "2026-08-06T13:24:10Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Shibby
products:
  - Tomato (1.28.0000)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Executing a manipulation of the argument wan_iface can lead to os command injection.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The manipulation of the argument ppp_custom results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19034
    cvss: 7.2
  - id: CVE-2026-19035
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19034
  - https://gitee.com/WH-YHUST/tomato-rc-qos-ppp-cve/blob/master/advisories/en/01-new_qoslimit_stop.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19035
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19036
  - https://gitee.com/WH-YHUST/tomato-rc-qos-ppp-cve/blob/master/advisories/en/03-sub_40F88C-pppd.md
  - https://vuldb.com/cve/CVE-2026-19036
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Migrate deprecated Shibby Tomato 1.28.0000 firmware to FreshTomato
      owner: IT Operations
      due: 7d
      evidence: Project is superseded by FreshTomato
  mitigation_plan:
    - priority: immediate
      action: Disable external WAN management interface access
      owner: IT Operations
      addresses: CVE-2026-19034
      evidence: Attack can be launched remotely
updates:
  - at: "2026-08-06T13:24:01Z"
    level: L2
    summary: added CVE-2026-19035
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19035
  - at: "2026-08-06T13:24:10Z"
    level: L2
    summary: added coverage for Tomato (1.28.0000)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19036
---

Shibby Tomato version 1.28.0000 contains a critical vulnerability involving OS command injection within the new_qoslimit_stop function located in the script /tmp/qoslimittc_stop.sh. An attacker can reach this function by providing malicious input to the wan_iface argument. Because this script executes system-level commands, manipulating this input allows for arbitrary command execution on the underlying Linux-based networking device. This vulnerability is of significant concern as the affected software is widely deployed on home and small-office wireless routers. The project has been superseded by FreshTomato, and users are advised to migrate, as no patches are expected for this legacy firmware. Publicly available exploit proof-of-concept code has been disclosed, increasing the likelihood of opportunistic exploitation in the wild.

## Attack Chain

1. The attacker identifies a target device running the legacy Shibby Tomato firmware version 1.28.0000.
2. The attacker gains access to the administrative web interface of the router (or interacts with the interface if exposed to the WAN).
3. The attacker identifies the request handler responsible for triggering QoS settings, specifically targeting the new_qoslimit_stop function.
4. The attacker crafts an HTTP request containing an injected payload within the 'wan_iface' parameter.
5. The web server process passes the attacker-supplied input directly to the /tmp/qoslimittc_stop.sh shell script without sufficient sanitization.
6. The shell script executes the payload with the privileges of the web service account.
7. The attacker establishes a reverse shell or executes secondary payloads to maintain persistence or exfiltrate configuration data.
8. The final objective is full compromise of the networking device to facilitate man-in-the-middle attacks or lateral movement within the local network.

## Impact

Successful exploitation allows an attacker to execute arbitrary OS commands with elevated privileges on the target router. This provides complete control over the device, enabling traffic interception, password extraction, configuration modification, and the use of the router as a pivot point for further attacks on the internal network. Given the ubiquity of these devices, this vulnerability poses a high risk to small-office and residential environments.

## Recommendation

Prioritized actions for security operations and IT management:
* Migrate all devices currently running Shibby Tomato 1.28.0000 to the active FreshTomato distribution or other supported firmware as the project is superseded.
* Disable remote management access on the router's web interface to mitigate external exploitation risks (CVE-2026-19034).
* Monitor firewall logs for unexpected outbound traffic from router management interfaces to unknown remote endpoints.
