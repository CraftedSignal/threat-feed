---
title: Remote Code Execution in ipTIME A3004T EAD Service
slug: 2026-08-iptime-rce
description: The ipTIME A3004T router (firmware 14.19.0) is vulnerable to pre-authentication remote code execution via a flaw in the EAD service, allowing root command injection.
date: "2026-08-17T14:54:27Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Paccaron
tags:
  - remote-code-execution
  - router-vulnerability
  - command-injection
vendors:
  - ipTIME
products:
  - A3004T (14.19.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote attacker can send a crafted EAD_TYPE_SEND_CMD packet to execute arbitrary commands on the device with root privileges.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52644
rules:
  - title: Detect Exploitation of EAD Service Command Injection
    description: Detects potential command injection attempts against the ipTIME EAD service via UDP port 56026.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block inbound UDP port 56026 at perimeter firewall
      owner: IT Operations
      due: 24h
      evidence: Service binds to UDP port 56026 and lacks IP filtering
  mitigation_plan:
    - priority: immediate
      action: Disable or firewall the EAD service on affected ipTIME routers
      owner: IT Operations
      addresses: ipTIME A3004T RCE
      evidence: Exploit targets exposed EAD service
---

A publicly disclosed vulnerability in the ipTIME A3004T router (firmware version 14.19.0) allows for unauthenticated remote code execution (RCE). The flaw resides in the EAD service, which listens on UDP port 56026. The vulnerability stems from an insecure implementation of the handle_send_cmd() function (lines 473-580 in ead.c), where user-controlled input provided in an EAD_TYPE_SEND_CMD packet is passed directly to the system() function without sanitization. This permits an attacker to execute arbitrary commands with root privileges. Additional vectors identified in the source include buffer overflows, format string vulnerabilities, and path traversal within the EAD service components. Because the EAD service does not implement source IP filtering, any remote attacker can target this service directly.

## Attack Chain

1. Attacker performs reconnaissance to identify ipTIME A3004T devices reachable via UDP port 56026.
2. Attacker crafts a malicious EAD_TYPE_SEND_CMD packet (0x0a command code).
3. The crafted packet includes a semi-colon followed by the target command to achieve command injection.
4. The packet is transmitted via UDP to the target device on port 56026.
5. The EAD service's handle_send_cmd() function receives and processes the unsanitized input.
6. The system() binary is invoked by the service, executing the injected command.
7. Attacker gains arbitrary code execution with root-level privileges on the device.

## Impact

Successful exploitation results in full device compromise, allowing an attacker to execute arbitrary commands with root privileges. This grants total control over the router, facilitating traffic interception, internal network pivoting, and denial of service. The vulnerability affects the ipTIME A3004T specifically on firmware 14.19.0.

## Recommendation

Prioritized, concrete actions for detection and mitigation:
* Block inbound traffic to UDP port 56026 at the network perimeter.
* Audit ipTIME A3004T devices for firmware version 14.19.0 and apply patches if available from the vendor.
* Deploy network intrusion detection signatures to identify UDP packets containing the string "EAD_TYPE_SEND_CMD" followed by shell metacharacters like ";".
* Monitor network traffic for unusual payloads targeting UDP port 56026.
