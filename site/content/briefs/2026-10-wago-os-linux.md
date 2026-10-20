---
brief_id: brief-2026-10-20-wago-os-linux
event_id: brief-2026-10-20-wago-os-linux
revision: 1
activity_at: "2026-10-20T17:31:34Z"
title: 'WAGO OS Linux: Web-Based Management OS command injection (CVE-2026-80466, CVE-2026-88850)'
slug: 2026-10-wago-os-linux
description: Multiple vulnerabilities in WAGO industrial controller firmware allow an authenticated low-privileged user to achieve root-level OS command injection and bypass configuration authorization checks.
date: "2026-10-20T17:31:34Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - ics
  - scada
  - vulnerability
  - command-injection
vendors:
  - WAGO
products:
  - CC100 (< 4.10.0)
  - PFC100 G2 (< 4.10.0)
  - PFC200 G2 (< 4.10.0)
  - TP600 (< 4.10.0)
  - Edge Controller (< 4.10.0)
  - WP400 (< 4.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticated low-privileged user to bypass intended privilege boundaries.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: allows a low-privileged remote attacker to inject shell commands into routing parameters.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: processed by a privileged root helper script.
    confidence_band: high
cves:
  - id: CVE-2026-80466
    kev_status: unknown
  - id: CVE-2026-88850
    kev_status: unknown
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-293-02
  - https://www.wago.com/de/d/15739#versions
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all WAGO controller firmware to version 4.10.0 or higher
      owner: IT Operations
      due: 72h
      evidence: Mitigation recommendation from CISA/WAGO
  mitigation_plan:
    - priority: immediate
      action: Implement network segmentation and VPN access for WBM interfaces
      owner: IT Operations
      addresses: CVE-2026-80466
      evidence: Security manual recommendations from vendor
---

Two security vulnerabilities, CVE-2026-80466 and CVE-2026-88850, affect the Web-Based Management (WBM) interface of multiple WAGO hardware controllers, including the CC100, PFC100 G2, PFC200 G2, TP600, Edge Controller, and WP400 series. These devices, which run WAGO OS Linux, are widely deployed across critical infrastructure sectors such as energy, water and wastewater, and manufacturing. The flaws allow an authenticated, low-privileged remote attacker to bypass intended privilege boundaries. Specifically, insufficient input validation in the routing configuration interface allows for OS command injection, where malicious payloads are written to configuration files and subsequently executed by a root-level helper script. Additionally, a secondary vulnerability impacts the authorization model for PROFIBUS configuration management, allowing unauthorized administrative changes. Organizations using affected firmware versions (1.0.0 through 4.10.0) are at risk of complete device compromise.

## Attack Chain

1. Attacker gains authenticated access to the Web-Based Management (WBM) interface of the WAGO controller using compromised or default credentials.
2. Attacker navigates to the routing configuration section of the WBM interface.
3. Attacker crafts a malicious payload containing shell metacharacters injected into a routing parameter field.
4. The WBM interface fails to sanitize the input and stores the malicious payload into a persistent configuration file on the system.
5. A privileged root helper script periodically reads the configuration file for system updates or network synchronization.
6. The root helper script interprets and executes the embedded malicious payload with root-level privileges.
7. The attacker achieves arbitrary code execution as the root user, facilitating unauthorized system configuration or full control over the industrial controller.

## Impact

The vulnerabilities represent a significant risk to industrial operations. Successful exploitation allows an authenticated attacker to execute arbitrary commands with root privileges on the device. Given the deployment of these controllers in critical infrastructure sectors - including energy, water, and transportation - this could lead to operational disruption, loss of control over industrial processes, or the manipulation of safety-critical parameters.

## Recommendation

1. Upgrade all affected WAGO controllers to firmware version 4.10.0 (FW32) or higher immediately to address CVE-2026-80466 and CVE-2026-88850.
2. Restrict network access to the WBM interface to authorized management subnets only via firewall rules or physical network segmentation.
3. Implement VPN access for remote management to ensure that WBM interfaces are not exposed directly to the internet.
4. Audit access logs for the WBM interface to detect abnormal authentication patterns or attempts to modify routing and PROFIBUS configurations by non-administrative users.
5. Review device manuals (specifically Sections 6 and 7 regarding security and VPN recommendations) for further hardening guidance provided by the vendor.
