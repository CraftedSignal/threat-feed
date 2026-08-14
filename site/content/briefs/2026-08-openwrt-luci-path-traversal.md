---
title: Path Traversal in luci-app-openvpn via instance_name2 Parameter
slug: 2026-08-openwrt-luci-path-traversal
description: An authenticated path traversal vulnerability in the luci-app-openvpn component of OpenWrt allows remote attackers to write arbitrary files to the filesystem and achieve persistent root-level code execution.
date: "2026-08-14T00:05:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - openwrt
  - network-security
vendors:
  - OpenWrt
products:
  - luci-app-openvpn
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Attackers can upload malicious payloads to gain persistent root code execution by placing SSH keys in system directories accessible on reboot.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505.002
    technique_name: 'Server Software Component: Transport Agent'
    evidence: luci-app-openvpn fails to properly validate the instance_name2 parameter during file upload, allowing authenticated users to perform path traversal and write arbitrary files outside the intended directory.
    confidence_band: high
cves:
  - id: CVE-2026-72841
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72841
  - https://github.com/openwrt/luci/security/advisories/GHSA-jjcx-c284-2qv8
  - https://www.vulncheck.com/advisories/luci-app-openvpn-path-traversal-rce-via-instance-name2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable OpenWrt devices
      owner: IT Operations
      due: 48h
      evidence: Critical CVE-2026-72841
---

The luci-app-openvpn package, part of the OpenWrt LuCI web interface, is susceptible to a path traversal vulnerability identified as CVE-2026-72841. This vulnerability exists due to improper validation of the 'instance_name2' parameter during file upload operations. An authenticated user can supply crafted input to this parameter to navigate outside the intended upload directory, enabling the writing of files to arbitrary locations on the underlying system. This flaw is particularly dangerous as it allows attackers to place malicious payloads, such as SSH authorized keys, into system-level directories that persist across reboots, ultimately leading to full system compromise and root-level code execution. The vulnerability has been assigned a CVSS v3.1 score of 9.9, reflecting its critical impact on system integrity and availability.

## Attack Chain

1. Attacker authenticates to the OpenWrt LuCI web interface with valid credentials.
2. Attacker initiates a file upload action within the OpenVPN instance configuration module.
3. Attacker intercepts the HTTP POST request to the web interface.
4. Attacker modifies the 'instance_name2' parameter to include directory traversal sequences (e.g., ../../../).
5. Attacker includes a malicious payload, such as a public SSH key, in the upload body.
6. The web application fails to sanitize the path, writing the payload to a system directory like '/etc/dropbear/authorized_keys'.
7. The system applies the new configuration, effectively granting the attacker SSH access.
8. Attacker logs in via SSH to achieve persistent root access on the network device.

## Impact

Successful exploitation results in full device compromise, allowing unauthorized persistent access and potential lateral movement within the network. Because OpenWrt devices often function as edge routers and firewalls, this vulnerability could be used to intercept or manipulate traffic, exfiltrate sensitive data, or bypass existing security perimeters for an entire organization.

## Recommendation

Prioritize patching of all OpenWrt instances. If immediate patching is not possible, disable the LuCI web interface for untrusted users or restrict administrative access to a hardened management network. Monitor system logs for unauthorized modifications to sensitive configuration files within '/etc/'.
