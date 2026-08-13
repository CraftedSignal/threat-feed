---
title: Fortinet Authentication Vulnerabilities in FortiWeb and FortiManager
slug: 2026-08-fortinet-auth-flaws
description: Fortinet has patched multiple high-severity vulnerabilities, including authentication bypasses in FortiWeb and FortiManager, alongside a buffer overflow in FortiClient for Windows.
date: "2026-08-13T11:39:55Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Fortinet
products:
  - FortiWeb
  - FortiManager
  - FortiClient
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote, unauthenticated attacker could exploit the flaw, tracked as CVE-2026-26035, to log in to the FortiWeb GUI/CLI with a random username and password.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Fortinet also patched a high-severity buffer overflow bug (CVE-2026-70465) in FortiClient for Windows that could allow unauthenticated attackers who can modify or craft DNS responses to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-26035
    cvss: 9.8
  - id: CVE-2026-70468
    cvss: 8.1
  - id: CVE-2026-70465
    cvss: 8.1
references:
  - https://www.securityweek.com/fortinet-patches-authentication-flaws-in-fortiweb-and-fortimanager/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch FortiWeb, FortiManager, and FortiClient systems according to the vendor release notes.
      owner: IT Operations
      due: 48h
      evidence: Fortinet announced patches for eight vulnerabilities across its products.
    - action: Audit FortiWeb configurations for enabled wildcard administrative groups.
      owner: Security Operations
      due: 24h
      evidence: As a workaround, the company recommends disabling the wildcard setting.
---

Fortinet has released security updates addressing eight vulnerabilities across its product portfolio. The most significant items include two high-severity authentication issues. CVE-2026-26035 affects FortiWeb deployments where the 'wildcard' setting is enabled for administrator accounts, allowing unauthenticated remote attackers to authenticate to the GUI or CLI using arbitrary credentials. A second issue, CVE-2026-70468, affects FortiManager, providing an authentication bypass that allows remote attackers to impersonate managed FortiGate appliances, provided a specific CLI option is enabled and the attacker possesses a valid certificate. Additionally, FortiClient for Windows is impacted by CVE-2026-70465, a high-severity buffer overflow vulnerability exploitable via crafted DNS responses, which could lead to arbitrary code execution. Organizations should prioritize patching or applying workarounds, such as disabling the wildcard administrative settings in FortiWeb.

## Impact

Successful exploitation of these vulnerabilities could lead to full administrative unauthorized access to FortiWeb and FortiManager appliances, or remote code execution on FortiClient endpoints. These vulnerabilities expose critical security infrastructure to unauthorized manipulation, administrative takeover, and potential lateral movement within the network. There is currently no evidence of exploitation in the wild for any of the patched vulnerabilities.

## Recommendation

* Apply the vendor-supplied patches for FortiWeb (versions 8.0.3, 7.6.7, 7.4.12, 7.2.13), FortiManager, and FortiClient immediately.
* For FortiWeb, review configurations to ensure the 'wildcard' setting for Admin User Groups is disabled if not strictly required by the organization's identity architecture.
* Monitor network traffic for anomalous DNS responses or attempts to interact with FortiManager administrative interfaces that originate from unauthorized or unexpected certificate-bearing clients.
* Monitor system logs for unexpected administrative login events (e.g., successful logins with unknown or non-standard usernames) specifically targeting FortiWeb and FortiManager administrative services.
