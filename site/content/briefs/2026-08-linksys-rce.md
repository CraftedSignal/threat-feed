---
title: Unauthenticated OS Command Injection in Linksys E1200
slug: 2026-08-linksys-rce
description: Linksys E1200 routers running firmware v2.0.04 and earlier are vulnerable to unauthenticated remote command execution via the tmUnblock.cgi endpoint.
date: "2026-08-31T13:03:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:h:linksys:e1200:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linksys:e1200_firmware:2.0.11.001:*:*:*:*:*:*:*
tags:
  - webapps
  - cve-2025-60689
  - command-injection
vendors:
  - Linksys
products:
  - E1200 (<= 2.0.04)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit this by sending a crafted HTTP POST request to the tmUnblock.cgi endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The vulnerability allows an attacker to inject shell metacharacters and commands, allowing for arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2025-60689
    cvss: 5.4
    epss: 0.0819
references:
  - https://www.exploit-db.com/exploits/52660
rules:
  - title: Detect CVE-2025-60689 Exploitation - HTTP POST to /tmUnblock.cgi
    description: Detects exploitation of CVE-2025-60689 - HTTP POST request to /tmUnblock.cgi containing shell metacharacters in the ttcp_ip parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for malicious POST requests.
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies tmUnblock.cgi as the vulnerable entry point.
  hunt_leads:
    - lead: Search for outbound connections from Linksys devices on port 8888 or similar.
      technique_id: T1071.001
      data_needed:
        - Network flow logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit code uses port 8888 for incoming reverse shell connections.
  mitigation_plan:
    - priority: immediate
      action: Isolate legacy hardware (E1200) from internet-facing network segments.
      owner: IT Operations
      addresses: CVE-2025-60689
      evidence: Vulnerability allows unauthenticated RCE on the device.
---

Linksys E1200 routers, specifically those running firmware version 2.0.04 and earlier, are susceptible to an unauthenticated OS command injection vulnerability (CVE-2025-60689). The vulnerability exists within the tmUnblock.cgi script, which fails to properly sanitize input provided to the ttcp_ip parameter during an HTTP POST request. By injecting shell metacharacters and commands into this parameter, an unauthenticated attacker can achieve arbitrary command execution with high privileges on the underlying Linux-based firmware. A proof-of-concept exploit is publicly available, which leverages this flaw to establish a reverse shell connection to an attacker-controlled listener. This vulnerability poses a significant risk to internal networks where these devices are deployed, as they often serve as the perimeter or routing gateway.

## Attack Chain

1. The attacker identifies a target Linksys E1200 device accessible over the network (LAN or WAN).
2. The attacker prepares a payload containing a shell script string, such as a reverse shell setup using mkfifo and telnet.
3. The attacker crafts an HTTP POST request targeting the /tmUnblock.cgi endpoint.
4. The malicious shell commands are injected into the ttcp_ip parameter within the request body.
5. The router processes the POST data and passes the unsanitized ttcp_ip value to a system call.
6. The injected commands execute with elevated privileges on the router.
7. The final command (e.g., telnet) connects back to the attacker's listener, providing an interactive command shell.

## Impact

Successful exploitation allows for full control of the router, potentially enabling an attacker to intercept network traffic, modify DNS settings, pivot into the internal network, or permanently disable the device. The vulnerability affects all Linksys E1200 devices running firmware version 2.0.04 or older, which are common in small office and home office (SOHO) environments.

## Recommendation

1. Restrict access to the router management interface to trusted internal IP addresses only.
2. If a firmware update is unavailable from the vendor, isolate the affected Linksys E1200 device from public-facing segments.
3. Deploy web application firewall or IDS/IPS signatures to detect POST requests to /tmUnblock.cgi containing shell metacharacters in the ttcp_ip parameter.
4. Monitor for unexpected outbound connections from router hardware, particularly those utilizing the telnet protocol, as indicated in the CVE-2025-60689 exploit PoC.
