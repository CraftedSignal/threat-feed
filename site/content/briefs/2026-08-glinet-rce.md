---
title: Command Injection Vulnerability in GL.iNet AX1800 RPC Endpoint
slug: 2026-08-glinet-rce
description: An authenticated remote command injection vulnerability in the RPC component of GL.iNet AX1800 routers (firmware <= 4.8.3) allows attackers to execute arbitrary system commands via the 'remove_rule' function.
date: "2026-08-04T17:25:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - GL.iNet
products:
  - AX1800
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument args.id leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18787
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18787
  - https://vuldb.com/vuln/385788
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update firmware on all GL.iNet AX1800 devices.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18787 remediation
  hunt_leads:
    - lead: Search logs for unusual RPC requests containing shell metacharacters.
      technique_id: T1059
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states command injection via args.id
  mitigation_plan:
    - priority: immediate
      action: Disable external access to management and RPC interfaces.
      owner: IT Operations
      addresses: CVE-2026-18787
      evidence: Remote attack surface reduction
---

A command injection vulnerability (CVE-2026-18787) has been identified in GL.iNet AX1800 routers running firmware versions up to 4.8.3. The flaw exists within the RPC endpoint component, specifically in the `remove_rule` function defined in `/usr/share/gl-ngx/oui-rpc.lua`. Attackers can leverage improper neutralization of the `args.id` argument to inject and execute arbitrary system commands. This vulnerability is remotely exploitable by an authenticated user. Given that public exploit code is available for this vulnerability, defenders should prioritize patching affected devices to the latest available firmware version to mitigate the risk of unauthorized system access and full device compromise.

## Attack Chain

1. Attacker establishes an authenticated session with the GL.iNet router web management interface or RPC API.
2. Attacker crafts a malicious request targeting the RPC endpoint.
3. Attacker injects shell metacharacters into the `args.id` parameter of the `remove_rule` RPC call.
4. The router's `/usr/share/gl-ngx/oui-rpc.lua` script processes the `args.id` argument without sufficient input sanitization.
5. The underlying system passes the unsanitized input to a command execution function, resulting in OS command execution with the privileges of the RPC service.
6. Attacker gains persistent code execution on the router, potentially allowing for lateral movement or traffic interception.

## Impact

Successful exploitation allows for complete compromise of the affected GL.iNet AX1800 router. Impact includes full control over the device, potential exfiltration of network traffic, and use of the router as a pivot point for further attacks on the internal network.

## Recommendation

* Apply the latest firmware updates provided by GL.iNet for the AX1800 to remediate CVE-2026-18787.
* Restrict access to the router's management interface and RPC endpoints to trusted IP addresses only.
* Monitor for suspicious RPC calls to the management interface that deviate from established administrative baseline behavior.
