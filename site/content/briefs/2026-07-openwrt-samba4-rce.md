---
title: OpenWrt luci-app-samba4 Vulnerability Allows Remote Command Execution
slug: 2026-07-openwrt-samba4-rce
description: A vulnerability in OpenWrt's luci-app-samba4, identified as CVE-2026-59260, allows authenticated delegated users to achieve remote command execution on the Samba daemon by leveraging improper ACLs that grant `file.exec` permission on `/usr/sbin/smbd`.
date: "2026-07-12T12:25:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openwrt
  - samba
  - cve
  - rce
  - network
  - linux
vendors:
  - OpenWrt
products:
  - luci-app-samba4
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can pass arbitrary Samba global options such as message command to a root smbd process, triggering command execution when SMB protocol messages are processed.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing authenticated delegated users to execute the Samba daemon with caller-controlled command-line arguments... to a root smbd process
    confidence_band: high
cves:
  - id: CVE-2026-59260
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59260
rules:
  - title: Detects CVE-2026-59260 Exploitation - smbd with message command
    description: Detects CVE-2026-59260 exploitation - execution of the smbd daemon with the 'message command' global option, indicative of command injection via improper ACLs in luci-app-samba4.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A high-severity vulnerability, CVE-2026-59260, has been identified in OpenWrt's luci-app-samba4 package, which serves as a web interface for Samba. This flaw stems from an improper `read` ACL that inadvertently grants `file.exec` permission on the `/usr/sbin/smbd` daemon. This misconfiguration allows authenticated delegated users to execute the Samba daemon with caller-controlled command-line arguments. Attackers can leverage this by passing arbitrary Samba global options, such as the `message command` parameter, to a root `smbd` process. This injection ultimately triggers command execution on the underlying OpenWrt device when SMB protocol messages are processed, leading to remote code execution. This vulnerability poses a significant risk to OpenWrt systems using the vulnerable package, enabling attackers to gain full control over the device.

## Attack Chain

1. An attacker obtains credentials for an authenticated delegated user on an OpenWrt device running `luci-app-samba4`.
2. The attacker leverages the improper `read` ACL within `luci-app-samba4` that affects the `/usr/sbin/smbd` executable.
3. The misconfigured ACL grants the authenticated user `file.exec` permission on the `/usr/sbin/smbd` daemon, allowing them to initiate its execution.
4. The attacker executes the `/usr/sbin/smbd` process, providing specific command-line arguments that are under their control.
5. During the execution, the attacker injects malicious Samba global options, such as `-o "message command = /path/to/arbitrary/script.sh"`, into the `smbd` process.
6. The `smbd` process, running with root privileges, processes subsequent SMB protocol messages containing the injected `message command`.
7. The arbitrary command specified in the `message command` option is then executed with root privileges on the OpenWrt device.
8. The attacker achieves remote code execution (RCE), gaining full control over the compromised OpenWrt system.

## Impact

Successful exploitation of CVE-2026-59260 allows an authenticated delegated user to achieve remote code execution with root privileges on the OpenWrt device. This level of compromise grants the attacker complete control over the network device. The impact includes, but is not limited to, unauthorized access to network resources, manipulation or exfiltration of sensitive data, establishment of persistent backdoors, and the ability to pivot to other systems within the network. This could lead to significant data breaches, service disruptions, or further attacks on connected infrastructure.

## Recommendation

* Patch CVE-2026-59260 by updating the `luci-app-samba4` package on all affected OpenWrt devices immediately.
* Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious `smbd` process creations.
* Enable comprehensive process creation logging for Linux systems to capture full command-line arguments for processes like `smbd`.
