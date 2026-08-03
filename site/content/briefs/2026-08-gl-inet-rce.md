---
title: Remote Command Injection in GL-iNet GL-MT3000 Firmware
slug: 2026-08-gl-inet-rce
description: A critical command injection vulnerability in the GL-iNet GL-MT3000 router firmware (up to 4.4.5) allows remote, unauthenticated attackers to execute arbitrary commands via the /cgi-bin/glc binary.
date: "2026-08-03T20:05:56Z"
lastmod: "2026-08-03T20:06:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
tags:
  - cve-2026-18612
  - remote-code-execution
  - command-injection
  - router
  - cve-2026-18614
  - network-device
  - rce
  - network-security
  - cve-2026-18615
vendors:
  - GL-iNet
products:
  - GL-MT3000
  - GL-MT3000 (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation causes command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18612
    cvss: 9.8
  - id: CVE-2026-18613
    cvss: 9.8
  - id: CVE-2026-18616
    cvss: 9.8
  - id: CVE-2026-18614
    cvss: 9.8
  - id: CVE-2026-18615
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18612
  - https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/plugins_package_name_glc_rce/CVE.md
  - https://vuldb.com/vuln/385532
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18613
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18614
  - https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/s2s_enable_echo_server_glc_rce/CVE.md
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18615
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18616
iocs:
  - type: url
    value: https://github.com/StrTzz123/iot_vul/blob/main/GL-iNet/MT3000/4.4.5/wg_set_peer_rce/CVE.md
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-18612 Exploitation - Command Injection via /cgi-bin/glc
    description: Detects suspicious HTTP POST requests to the /cgi-bin/glc binary containing shell metacharacters indicative of command injection exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-18614 Exploitation - Command Injection in /cgi-bin/glc
    description: Detects attempts to exploit CVE-2026-18614 by identifying shell metacharacters in the port parameter passed to the /cgi-bin/glc endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch GL-MT3000 devices to firmware versions > 4.4.5
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions up to 4.4.5 are affected.
    - action: Monitor web logs for /cgi-bin/glc exploitation patterns
      owner: SOC
      due: 4h
      evidence: Exploit code is public.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to web management port 80/443
      owner: IT Operations
      addresses: CVE-2026-18612
      evidence: Vulnerability allows remote execution via web interface.
updates:
  - at: "2026-08-03T20:06:00Z"
    level: L2
    summary: added CVE-2026-18613; gl-mt3000 version <= 4.4.5
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18613
  - at: "2026-08-03T20:06:10Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-18614 Exploitation - Command Injection in /cgi-bin/glc'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18614
  - at: "2026-08-03T20:06:18Z"
    level: L2
    summary: 'merged source coverage: Remote Command Injection in GL-iNet GL-MT3000'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18615
  - at: "2026-08-03T20:06:20Z"
    level: L2
    summary: poc_available; added CVE-2026-18614 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18616
---

A critical security vulnerability (CVE-2026-18612) has been identified in the GL-iNet GL-MT3000 router firmware, affecting all versions up to and including 4.4.5. The vulnerability resides within the 'plugins.so' native plugin, specifically impacting the 'plugins.remove_package' and 'plugins.install_package' functions invoked via the '/cgi-bin/glc' CGI binary. An unauthenticated, remote attacker can leverage this flaw to perform command injection, resulting in full remote code execution on the device.

Public exploit code has been released, significantly lowering the barrier for exploitation. Given the prevalence of this hardware in edge and small-office network environments, organizations utilizing these devices should prioritize patching or restricting access to the management interface. The vendor has acknowledged the flaw, and users are advised to update to the latest available firmware version that addresses this issue.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.8 (Critical), indicating high risk for confidentiality, integrity, and availability. Successful exploitation grants an attacker administrative control over the router, enabling further network compromise, traffic interception, or the deployment of persistent implants within the affected network.

## Recommendation

- Update GL-iNet GL-MT3000 firmware to the latest version immediately to remediate CVE-2026-18612.
- Restrict access to the router's web management interface to trusted internal IP ranges or VPNs.
- Deploy web application firewall or IDS/IPS signatures capable of detecting anomalous POST requests targeting '/cgi-bin/glc' with suspicious shell metacharacters (e.g., ;, |, &&).
- Deploy the provided Sigma rule to monitor for suspicious attempts to access the vulnerable CGI binary.
