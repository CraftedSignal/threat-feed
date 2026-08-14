---
title: Remote OS Command Injection in Baicells EG3661M LuCI Interface
slug: 2026-08-baicells-rce
description: The Baicells EG3661M router running firmware BaiCE_BQ6_2.0.5.3_NA is vulnerable to unauthenticated or privileged OS command injection via the LuCI web interface.
date: "2026-08-14T04:06:03Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Baicells
products:
  - EG3661M
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Such manipulation of the argument MaxHops/Timeout/Size leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19771
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19771
  - https://vuldb.com/vuln/389685
rules:
  - title: Detects CVE-2026-19771 Exploitation - OS Command Injection in LuCI
    description: Detects attempts to exploit CVE-2026-19771 by sending HTTP requests to /cgi-bin/luci containing shell metacharacters in specific parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
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
    - action: Restrict access to the management interface for Baicells EG3661M routers
      owner: IT Operations
      due: 24h
      evidence: High CVSS severity and public exploit availability
  hunt_leads:
    - lead: Search web logs for requests to /cgi-bin/luci containing ; or &
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability analysis indicates command injection via URL parameters
  mitigation_plan:
    - priority: immediate
      action: Firewall rule to block external access to device management ports
      owner: IT Operations
      addresses: CVE-2026-19771
      evidence: Remotely exploitable vulnerability
---

A remote OS command injection vulnerability (CVE-2026-19771) has been identified in the Baicells EG3661M wireless router, specifically affecting firmware version BaiCE_BQ6_2.0.5.3_NA. The flaw exists within the LuCI web interface component, specifically within the /cgi-bin/luci file. An attacker can trigger this vulnerability by manipulating specific input arguments, namely 'MaxHops', 'Timeout', or 'Size'. Successful exploitation allows for the execution of arbitrary operating system commands on the affected device. Public exploit code for this vulnerability is available, and the vendor has not provided a response or a patch as of the time of disclosure.

## Attack Chain

1. The attacker identifies an internet-facing Baicells EG3661M device running the vulnerable firmware.
2. The attacker navigates to the management interface hosted on the device.
3. The attacker prepares a crafted HTTP request targeting the /cgi-bin/luci endpoint.
4. The attacker injects malicious shell metacharacters into one of the vulnerable parameters: MaxHops, Timeout, or Size.
5. The web server process, executing with elevated privileges, improperly sanitizes the input before passing it to a system call.
6. The injected OS command is executed by the router's underlying operating system.
7. The attacker achieves persistent remote command execution to perform further malicious actions, such as configuration modification or credential theft.

## Impact

Successful exploitation results in full control over the affected Baicells EG3661M device. Given that these are routing and networking appliances, impact includes potential interception of network traffic, device bricking, or utilization of the router as a pivot point within the local network.

## Recommendation

Prioritize the isolation of the management interface of all Baicells EG3661M devices from the public internet. Ensure the management interface is only accessible via a secure, private network or VPN. Since the vendor has not provided a patch, consider upgrading to an alternative hardware solution or strictly enforcing access control lists (ACLs) to restrict access to the /cgi-bin/luci endpoint.
