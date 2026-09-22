---
title: Unauthenticated Remote Code Execution in D-Link DAP-1360
slug: 2026-09-dlink-rce
description: D-Link DAP-1360 firmware version 6.14 and earlier is susceptible to unauthenticated remote code execution via the web management interface, allowing root-level command injection.
date: "2026-09-22T14:36:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:dlink:dap-1360_firmware:*:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DAP-1360 (<= 6.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Allows remote attackers to execute arbitrary commands as root by sending crafted requests to the device's web management interface without valid credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Allows remote attackers to execute arbitrary commands as root.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Allows remote attackers to... persistently modify its configuration.
    confidence_band: high
cves:
  - id: CVE-2026-95675
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95675
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Isolate D-Link DAP-1360 management interfaces from the internet.
      owner: Network Security
      due: 24h
      evidence: CVE-2026-95675 allows unauthenticated RCE via management interface.
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to a version beyond 6.14.
      owner: IT Operations
      addresses: CVE-2026-95675
      evidence: Source identifies 6.14 and earlier as vulnerable.
---

D-Link DAP-1360 wireless access points running firmware version 6.14 and earlier contain a critical vulnerability in the device's web management interface. This flaw allows an unauthenticated, remote attacker to execute arbitrary system commands with root privileges by sending specially crafted HTTP requests to the web management portal. Successful exploitation provides the attacker with full control over the device, facilitating persistent configuration changes and the ability to utilize the affected hardware as a pivot point for lateral movement into the local network. As this vulnerability impacts the management interface directly, the device can be compromised without requiring valid administrative credentials.

## Attack Chain

1. Attacker performs network reconnaissance to identify D-Link DAP-1360 devices reachable via the web management interface.
2. Attacker probes the web interface to identify input parameters or endpoints vulnerable to command injection.
3. Attacker constructs a malicious HTTP request containing shell metacharacters targeted at the vulnerable management CGI or endpoint.
4. The web server process, running as root, fails to sanitize the input and executes the injected payload.
5. The device executes the attacker-supplied command, establishing an initial foothold.
6. Attacker modifies device configuration files to ensure persistence across reboots.
7. Attacker utilizes the compromised device as an internal jump host or proxy to scan and target other assets within the internal network.

## Impact

Successful exploitation results in total device compromise, allowing persistent unauthorized access to the network segment where the device is deployed. Threat actors can use the affected hardware for credential sniffing, traffic interception, or as a persistent gateway into secured network zones.

## Recommendation

Prioritize the identification and patching of all D-Link DAP-1360 devices within the environment. If immediate patching is not possible, disable the remote web management interface or restrict access to the device management IP address to a dedicated, isolated management VLAN using firewall controls.
