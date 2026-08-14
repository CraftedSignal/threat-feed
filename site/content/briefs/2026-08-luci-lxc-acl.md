---
title: Authorization Bypass and RCE in luci-app-lxc
slug: 2026-08-luci-lxc-acl
description: An ACL inconsistency in the OpenWrt luci-app-lxc package allows authenticated low-privileged users to achieve root code execution via path traversal and hook script manipulation.
date: "2026-08-14T00:05:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - OpenWrt
products:
  - luci-app-lxc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: luci-app-lxc contains an ACL inconsistency vulnerability that allows low-privileged authenticated LuCI users to access backend container management routes without proper authorization checks.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can exploit path traversal via /.%2E in the lxc_name parameter to escape container directories and control host-side scripts ... achieving root code execution on the OpenWrt host.
    confidence_band: high
cves:
  - id: CVE-2026-72842
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72842
  - https://github.com/openwrt/luci/security/advisories/GHSA-jf59-v86x-fwf2
rules:
  - title: Detect CVE-2026-72842 Exploitation - Path Traversal in lxc_name
    description: Detects exploitation of CVE-2026-72842 by identifying path traversal sequences in the lxc_name parameter within webserver logs
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all OpenWrt devices running luci-app-lxc
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-72842 critical vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict LuCI web access to trusted IPs only
      owner: IT Operations
      addresses: CVE-2026-72842
      evidence: Authorization bypass vulnerability requires access to web interface
---

The OpenWrt luci-app-lxc package contains a critical ACL inconsistency vulnerability that permits authenticated, low-privileged users to bypass authorization controls. This flaw specifically affects backend container management routes. By exploiting a path traversal vulnerability triggered via the `lxc_name` parameter, an attacker can escape the intended container isolation boundaries. 

The exploit utilizes the `/.%2E` sequence to traverse directories and gain access to host-level configurations. Once access is achieved, an attacker can manipulate host-side scripts, specifically those defined in `lxc.hook.start-host`. Successful exploitation results in arbitrary code execution with root privileges on the underlying OpenWrt host. This vulnerability has been assigned a CVSS v3.1 base score of 9.9, highlighting the severe risk to network infrastructure running affected OpenWrt firmware versions.

## Attack Chain

1. Attacker authenticates to the LuCI web interface with low-privileged credentials.
2. Attacker crafts a malicious request targeting backend container management routes.
3. Attacker injects a path traversal payload `/.%2E` into the `lxc_name` parameter.
4. The application fails to validate the input, allowing the attacker to escape the container directory structure.
5. Attacker locates the `lxc.hook.start-host` configuration file on the host filesystem.
6. Attacker overwrites or modifies the hook script to include arbitrary malicious commands.
7. The system triggers the hook script during a container start event.
8. The host executes the attacker-controlled script with root privileges, resulting in full system compromise.

## Impact

Successful exploitation of this vulnerability grants an attacker full root access to the OpenWrt host, which typically serves as the edge gateway or router. An attacker could intercept network traffic, modify firewall rules, establish persistent backdoor access, or use the device as a pivot point into the internal network. Given the typical placement of OpenWrt devices at the network perimeter, this represents a significant risk to the entire organizational infrastructure.

## Recommendation

* Update OpenWrt firmware to the latest version, ensuring the `luci-app-lxc` package is patched to the version addressing CVE-2026-72842.
* Restrict access to the LuCI web management interface to trusted internal management subnets via the host firewall (e.g., iptables or nftables rules).
* Audit logs for unauthorized access attempts to the container management backend routes.
* Disable the `luci-app-lxc` package if container management is not required on the device.
