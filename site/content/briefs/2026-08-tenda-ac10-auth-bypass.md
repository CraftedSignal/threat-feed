---
title: Authentication Bypass in Tenda AC10 Router
slug: 2026-08-tenda-ac10-auth-bypass
description: An improper authentication vulnerability in the Tenda AC10 router's httpd component allows remote, unauthenticated attackers to gain unauthorized access to the device.
date: "2026-08-16T02:22:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - authentication-bypass
  - cve-2026-19924
vendors:
  - Tenda
products:
  - AC10 (16.03.10.09_multi_TDE01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19924
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19924
  - https://github.com/teiwiet/tenda-ac10-vulnerabilities/blob/main/authen-bypass-tenda-ac10.md
  - https://vuldb.com/vuln/390174
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to management interfaces for all Tenda hardware.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19924 remote exploitation vector
  mitigation_plan:
    - priority: immediate
      action: Patch firmware if available; disable public management access
      owner: IT Operations
      addresses: CVE-2026-19924
      evidence: NVD vulnerability disclosure
---

A critical security vulnerability (CVE-2026-19924) has been identified in Tenda AC10 routers running firmware version 16.03.10.09_multi_TDE01. The flaw exists within the `R7WebsSecurityHandler` function of the `httpd` daemon. This vulnerability allows remote, unauthenticated attackers to bypass authentication mechanisms, granting them unauthorized access to the router's management interface or sensitive device settings. Publicly disclosed exploit code for this vulnerability is currently available, significantly lowering the barrier for exploitation. Given the network-facing nature of the affected service, this flaw poses a severe risk to device integrity and internal network visibility.

## Attack Chain

1. Attacker performs reconnaissance to identify Tenda AC10 devices reachable via the public internet.
2. Attacker initiates an HTTP connection to the target device's management web interface on port 80 or 443.
3. Attacker sends a crafted HTTP request designed to interact with the vulnerable `R7WebsSecurityHandler` function.
4. The `httpd` component fails to properly validate the authentication state during this request.
5. The vulnerability is triggered, allowing the attacker to bypass the standard login process.
6. Attacker gains session-level or administrative access to the device management panel.
7. Attacker performs unauthorized configuration changes, such as modifying DNS settings, exfiltrating credentials, or pivoting into the local network.

## Impact

Successful exploitation allows for full administrative control over the affected Tenda AC10 routers. Potential consequences include device hijacking, interception of network traffic, modification of DNS settings to facilitate man-in-the-middle (MitM) attacks, and unauthorized access to devices on the internal network. The vulnerability impacts residential and small-business environments where these routers are deployed.

## Recommendation

Prioritized actions for security operations and IT teams:
- Immediately restrict access to the Tenda AC10 management interface to internal or VPN-only networks.
- Check for and apply the latest firmware updates from Tenda to address CVE-2026-19924.
- Monitor logs for unusual HTTP traffic patterns originating from external IP addresses directed at the router's management interface.
- Audit network perimeter configurations to ensure management ports for networking hardware are not exposed to the public internet.
