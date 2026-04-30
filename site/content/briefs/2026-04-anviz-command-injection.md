---
title: Anviz CX2 Lite Authenticated Command Injection Vulnerability (CVE-2026-35682)
slug: 2026-04-anviz-command-injection
description: Anviz CX2 Lite is vulnerable to an authenticated command injection via the filename parameter, leading to arbitrary command execution and root-level access.
date: "2026-04-17T20:16:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - unauthorized-access
  - iot
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-35682
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35682
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
rules:
  - title: Detect Anviz CX2 Lite Command Injection Attempt
    description: Detects potential command injection attempts against Anviz CX2 Lite devices by monitoring for suspicious characters in the filename parameter within HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: Detect Anviz CX2 Lite Telnetd Startup via Command Injection
    description: Detects telnetd being started, indicating command injection on an Anviz CX2 Lite device.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-35682 describes an authenticated command injection vulnerability in Anviz CX2 Lite devices. An attacker with valid user credentials can inject arbitrary commands into the filename parameter, leading to remote code execution with root privileges. The vulnerability allows an attacker to execute commands like starting telnetd, effectively gaining complete control over the device. This poses a significant risk to organizations using vulnerable Anviz CX2 Lite devices for access control or time attendance, potentially leading to unauthorized access, data breaches, or denial-of-service conditions. The ICS-CERT advisory, ICSA-26-106-03, provides additional details.

## Attack Chain

1. An attacker gains valid credentials for an Anviz CX2 Lite device.
2. The attacker authenticates to the device's web interface or API.
3. The attacker identifies the vulnerable filename parameter in a specific request.
4. The attacker crafts a malicious request containing a command injection payload within the filename parameter (e.g., `filename=;telnetd -p 1337 -l /bin/sh;`).
5. The Anviz CX2 Lite device processes the request, improperly sanitizing the filename parameter.
6. The injected command executes with root privileges on the device.
7. The attacker uses the executed command to start a service like telnetd.
8. The attacker connects to the newly started service, gaining a root shell and complete control of the device.

## Impact

Successful exploitation of CVE-2026-35682 allows a remote attacker to gain root-level access to the Anviz CX2 Lite device. This can lead to complete system compromise, including unauthorized access to sensitive data, modification of device settings, and potential use of the device as a foothold for further attacks within the network. Given that these devices are often used for physical access control, this vulnerability could lead to unauthorized physical access to secured areas.

## Recommendation

*   Apply available patches or firmware updates from Anviz to remediate CVE-2026-35682. Contact Anviz directly through their website for support and remediation steps (https://www.anviz.com/contact-us.html).
*   Deploy the Sigma rule `Detect Anviz CX2 Lite Command Injection Attempt` to identify exploitation attempts against the device.
*   Monitor web server logs for suspicious requests containing command injection payloads in the filename parameter to identify potential exploitation attempts.
*   Review authentication logs for unauthorized access attempts to the Anviz CX2 Lite devices.
