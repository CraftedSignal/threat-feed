---
title: Remote Command Injection in D-Link DIR-895L
slug: 2026-09-dlink-command-injection
description: An unauthenticated remote command injection vulnerability in the D-Link DIR-895L router allows attackers to execute arbitrary code via a malicious Hostname argument in the udhcpcd component.
date: "2026-09-07T12:52:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:dlink:dir-895l_firmware:a1_102b07:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DIR-895L (A1_102b07)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument Hostname results in command injection. The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-86295
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86295
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory affected D-Link DIR-895L devices
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-86295 reporting
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable routers from internet-facing segments until patched
      owner: IT Operations
      addresses: CVE-2026-86295
      evidence: NVD vulnerability disclosure
---

A remote command injection vulnerability (CVE-2026-86295) has been identified in D-Link DIR-895L routers running firmware version A1_102b07. The flaw resides within the `sendACK` function in the `udhcpcd/serverpacket.c` file of the `udhcpcd` component. An unauthenticated attacker can trigger this vulnerability by sending a specially crafted DHCP request containing a malicious payload within the Hostname argument. This allows for arbitrary command execution on the target device with the privileges of the affected process. Given that the exploit code has been made publicly available, there is a significant risk of exploitation by threat actors targeting residential and small office/home office (SOHO) network infrastructure.

## Impact

Successful exploitation results in full remote control over the affected D-Link DIR-895L router. Attackers could leverage this access to intercept network traffic, redirect DNS queries, pivot into the local network, or incorporate the device into a botnet. This represents a critical risk to data confidentiality and integrity for any users on the local network managed by the vulnerable router.

## Recommendation

1. Inventory all D-Link DIR-895L devices within the network environment.
2. Restrict access to administrative interfaces and DHCP-related management ports to trusted IP ranges where possible.
3. Monitor for firmware updates from the vendor and apply patches immediately upon availability.
4. Isolate affected hardware from critical segments until a vendor-supplied update is verified and installed.
