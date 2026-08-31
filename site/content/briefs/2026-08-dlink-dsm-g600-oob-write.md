---
title: Remote Out-of-Bounds Write Vulnerability in D-Link DSM-G600
slug: 2026-08-dlink-dsm-g600-oob-write
description: A critical out-of-bounds write vulnerability in the D-Link DSM-G600 multipart handler allows remote attackers to compromise the device via the /load_file.cgi endpoint, with public exploit code currently available.
date: "2026-08-31T12:00:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:d_link:dsm_g600:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-appliance
vendors:
  - D-Link
products:
  - DSM-G600 (1.01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82680
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82680
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to /load_file.cgi on D-Link DSM-G600 devices using firewall or ACL rules.
      owner: IT Operations
      due: 24h
      evidence: The attack may be launched remotely via /load_file.cgi.
  mitigation_plan:
    - priority: immediate
      action: Decommission D-Link DSM-G600 devices or move to isolated network segments.
      owner: IT Operations
      addresses: CVE-2026-82680
      evidence: Vulnerability affects outdated 1.01 firmware of a legacy device.
---

D-Link DSM-G600 version 1.01 contains a critical vulnerability within the multipart handler component, specifically located in the /load_file.cgi script. This flaw allows a remote, unauthenticated attacker to trigger an out-of-bounds write condition. Because the device handles multipart requests, improper bounds checking during the processing of these requests enables the corruption of memory, which can lead to arbitrary code execution or permanent system instability. Public exploit code for this vulnerability is currently available, significantly lowering the barrier for exploitation by malicious actors. Given the nature of the device as a storage/network component, successful exploitation could provide an attacker with a foothold for lateral movement within the internal network or the exfiltration of stored data.

## Impact

Successful exploitation of CVE-2026-82680 allows for remote code execution on the affected D-Link DSM-G600 devices. This impact represents a high risk to organizational security, as compromised network storage devices can be leveraged for persistence, internal reconnaissance, or as a pivot point for further network attacks.

## Recommendation

Prioritize the decommissioning or isolation of legacy D-Link DSM-G600 devices, as version 1.01 is significantly outdated and lacks modern security hardening. For environments where the device cannot be decommissioned, ensure that the /load_file.cgi endpoint is not accessible from untrusted or public-facing network segments. Implement network-level access control lists (ACLs) to restrict traffic to the management interface of the device to known, authorized administrative IP addresses.
