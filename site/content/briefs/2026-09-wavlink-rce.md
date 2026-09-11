---
title: Unauthenticated Arbitrary File Write in WAVLINK Routers
slug: 2026-09-wavlink-rce
description: WAVLINK WN535M1 and WN535M3 routers are vulnerable to unauthenticated arbitrary file writes via the sync_server daemon, enabling attackers to gain root-level persistence.
date: "2026-09-11T17:13:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:wavlink:wn535m1:*:*:*:*:*:*:*:*
  - cpe:2.3:h:wavlink:wn535m3:*:*:*:*:*:*:*:*
tags:
  - network-security
  - remote-code-execution
  - cve-2026-89009
vendors:
  - WAVLINK
products:
  - WN535M1 (< M35M1_V250922)
  - WN535M3 (< M35M1_V250922)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The daemon, which runs as root and requires no authentication, accepts a 100-byte filename field in its protocol header without path canonicalization, allowing attackers to supply an absolute path.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
    evidence: allowing attackers to supply an absolute path and write arbitrary content to overwrite startup scripts or credential stores to achieve persistent system compromise.
    confidence_band: high
cves:
  - id: CVE-2026-89009
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89009
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade WAVLINK WN535M1 and WN535M3 firmware to M35M1_V250922
      owner: IT Operations
      due: 24h
      evidence: Source provided fixed firmware version M35M1_V250922 for CVE-2026-89009
  mitigation_plan:
    - priority: immediate
      action: Block TCP 13136 at the perimeter firewall
      owner: Network Security
      addresses: CVE-2026-89009
      evidence: sync_server daemon listens on TCP port 13136
---

WAVLINK WN535M1 and WN535M3 routers running firmware versions prior to M35M1_V250922 contain a critical vulnerability, tracked as CVE-2026-89009, which allows for unauthenticated arbitrary file write operations. The vulnerability exists within the sync_server daemon, which listens for connections on TCP port 13136. The daemon, which operates with root privileges, fails to perform path canonicalization on the filename field provided within its custom protocol header.

By sending a specially crafted 100-byte payload to the target device, a remote attacker can specify absolute file paths to overwrite critical system files. This enables the modification of startup scripts, configuration files, or credential stores. Successful exploitation grants an attacker persistent root-level access to the affected routing infrastructure, which can be utilized for traffic interception, credential harvesting, or as a pivot point for further lateral movement within the network. Defenders should prioritize patching and ensure that management interfaces and daemon ports are not exposed to untrusted networks.

## Impact

Successful exploitation of this vulnerability results in full administrative (root) control over the affected WAVLINK networking hardware. An attacker can achieve persistence, modify routing tables to intercept traffic, or extract device credentials, potentially leading to widespread compromise of the internal network segment connected to the router. As these devices are typically internet-facing edge components, the potential for mass exploitation by automated scanning is high.

## Recommendation

- Upgrade the firmware on all WAVLINK WN535M1 and WN535M3 devices to version M35M1_V250922 or later to address CVE-2026-89009.
- Apply network-level access control to restrict access to TCP port 13136, ensuring that the sync_server daemon is not reachable from the public internet or untrusted internal zones.
- Monitor network traffic for anomalous outbound connections originating from router infrastructure, which may indicate post-exploitation activity or C2 communication following a successful file overwrite.
