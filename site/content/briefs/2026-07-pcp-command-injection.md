---
title: Command Injection in PCP linux_sockets PMDA
slug: 2026-07-pcp-command-injection
description: A command injection vulnerability (CVE-2026-16524) in the PCP linux_sockets PMDA allows local attackers to execute arbitrary commands by injecting shell metacharacters into the network.persocket.filter metric.
date: "2026-07-30T07:20:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - pcp
  - linux
vendors:
  - Red Hat
products:
  - pcp
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat OpenShift Container Platform 4
affected_os:
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: A command injection flaw in PCP's linux_sockets PMDA allows malicious shell metacharacters via the network.persocket.filter metric.
    confidence_band: high
cves:
  - id: CVE-2026-16524
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16524
  - https://access.redhat.com/security/cve/CVE-2026-16524
  - https://bugzilla.redhat.com/show_bug.cgi?id=2506023
---

Performance Co-Pilot (PCP) contains a critical command injection vulnerability identified as CVE-2026-16524. The flaw resides within the linux_sockets Performance Metrics Domain Agent (PMDA). Specifically, the PMDA fails to properly validate input provided via the 'network.persocket.filter' metric. A local attacker with low-level privileges can craft malicious shell metacharacters and inject them into this metric. When the PCP agent refreshes its metrics, the underlying system executes these injected characters as commands with the privileges of the PMDA user. This vulnerability impacts multiple versions of Red Hat Enterprise Linux (RHEL 7 through 10) and OpenShift Container Platform, posing a significant risk for privilege escalation and unauthorized system activity on monitored hosts. Defenders must prioritize patching the 'pcp' package to mitigate this vector.

## Attack Chain

1. Attacker gains initial access to the target host with low-privileged user rights.
2. Attacker identifies that the PCP 'linux_sockets' PMDA is active and accepting metric configuration updates.
3. Attacker crafts a malicious string containing shell metacharacters (e.g., ;, &&, |).
4. Attacker writes this malicious string to the 'network.persocket.filter' metric configuration.
5. The PCP 'linux_sockets' PMDA process triggers a refresh of the metrics configuration.
6. The PMDA process parses the tainted 'network.persocket.filter' input without sanitization.
7. The system executes the embedded shell commands under the context of the PMDA service user.
8. Attacker achieves arbitrary command execution for further post-exploitation activities.

## Impact

Successful exploitation of CVE-2026-16524 allows an attacker to execute arbitrary commands on the affected system. Given that performance monitoring agents often run with specific service-level privileges, this can lead to full system compromise, exfiltration of sensitive monitoring data, or lateral movement within the environment. RHEL 7, 8, 9, and 10, along with OpenShift environments, are affected by this vulnerability.

## Recommendation

* Update the 'pcp' package to the latest version provided by Red Hat to patch CVE-2026-16524.
* Restrict write access to performance metric configuration files and directories to authorized administrative accounts only.
* Monitor for abnormal process execution spawned by PCP-related binaries, such as 'pmda' processes, using auditd or EDR telemetry.
* Audit existing 'network.persocket.filter' configurations for anomalous characters or suspicious commands.
