---
title: Command Injection in Teltonika RutOS via API Services
slug: 2026-10-teltonika-rutos-rce
description: Teltonika RutOS 00.07.06.21 is vulnerable to post-authentication command injection via the ipsec.lua and openvpn.lua modules, allowing arbitrary root command execution.
date: "2026-10-01T15:12:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - command-injection
  - industrial-security
vendors:
  - Teltonika
products:
  - RutOS (00.07.06.21)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The vulnerability summary states the issue is an OS command injection where the payload is passed to /bin/sh -c.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.001
    technique_name: 'Valid Accounts: Default Accounts'
    evidence: Exploitation requires authentication, necessitating a valid JWT obtained via login.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52692
  - https://0day-rubbish.com/blog/teltonika-rutos-ipsec-status-logread-command-injection
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Security
  immediate_actions:
    - action: Restrict web management interface access to authorized IP ranges.
      owner: Network Security
      due: 24h
      evidence: The vulnerable interface is the web management plane, reachable via the network.
  hunt_leads:
    - lead: Search web logs for HTTP requests to /api/ipsec/status/ or /api/openvpn/status/ containing special characters.
      technique_id: T1059.004
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation targets these specific URI patterns with shell-injected payloads.
  mitigation_plan:
    - priority: immediate
      action: Disable remote web management access if not required.
      owner: IT Operations
      addresses: Teltonika RutOS 00.07.06.21
      evidence: Exploit targets the web management API.
---

Teltonika RutOS version 00.07.06.21, primarily used in industrial RUT2XX and RUT9XX routers, contains multiple command injection vulnerabilities in its web management API. The vulnerabilities originate in the ipsec.lua and openvpn.lua service modules, which handle user-supplied input for the 'sid' parameter in API requests. These parameters are passed to the 'logread' system command via 'vuci.util.exec' without sufficient sanitization or the use of shell-quoting helpers. 

Because the 'uhttpd' web server runs with root privileges and lacks a user-drop directive, an authenticated attacker can trigger this vulnerability to execute arbitrary shell commands as root. The command output is captured and reflected back to the attacker in the HTTP JSON response, facilitating easier data exfiltration and further post-exploitation activity. The vulnerability affects the MIPS-based architecture common to these devices and was confirmed via dynamic analysis in a QEMU MIPS user-mode environment.

## Attack Chain

1. Attacker obtains valid administrative credentials for the RutOS web management interface via password spraying or credential stuffing.
2. Attacker logs into the web interface to obtain a valid JWT session token.
3. Attacker constructs a malicious URL path segment for the /api/ipsec/status/ or /api/openvpn/status/ endpoint.
4. The payload is crafted to include shell metacharacters such as single quotes and semicolons to escape the vulnerable 'logread' command arguments.
5. Attacker sends an authenticated GET request containing the injected payload to the target API endpoint.
6. The backend 'ipsec.lua' or 'openvpn.lua' service module unsafely concatenates the payload into a command executed by 'vuci.util.exec' (/bin/sh -c).
7. The system executes the injected arbitrary commands with root privileges.
8. The HTTP response body captures the command output within the JSON '.data.logs' field, providing immediate feedback to the attacker.

## Impact

Successful exploitation allows an attacker to achieve full remote code execution with root privileges on the industrial router. This can lead to complete device compromise, network traffic interception, modification of firewall and routing rules, and the ability to pivot into the internal OT/IT network segments where the router is deployed.

## Recommendation

1. Audit web management logs for administrative access originating from unauthorized or unusual source IPs.
2. Restrict access to the router's web management interface (uhttpd) to trusted internal management subnets.
3. Change default administrative credentials immediately if not already performed.
4. Monitor for HTTP POST/GET requests targeting /api/ipsec/status/ or /api/openvpn/status/ that contain suspicious shell metacharacters such as semicolons, single quotes, or common command syntax (e.g., 'id', 'cat').
