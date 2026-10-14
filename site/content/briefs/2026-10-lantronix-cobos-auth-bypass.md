---
title: Authentication Bypass in Lantronix CoBos Firmware
slug: 2026-10-lantronix-cobos-auth-bypass
description: Lantronix XPress-DR and XPress-DR-I devices running firmware version 8.1.0.0 and earlier are vulnerable to remote configuration manipulation via an unauthenticated UDP configuration protocol.
date: "2026-10-14T20:32:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - industrial-control-systems
  - network-security
  - embedded-devices
vendors:
  - Lantronix
products:
  - XPress-DR (<= 8.1.0.0)
  - XPress-DR-I (<= 8.1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can exploit this to read configuration data and persistently overwrite critical settings by sending specially crafted frames.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Changes to commit to EEPROM and persist across reboots.
    confidence_band: high
cves:
  - id: CVE-2026-109439
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109439
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block inbound and outbound UDP traffic on port 30718 from untrusted segments to all Lantronix XPress-DR devices.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109439 vulnerability in UDP configuration protocol.
  mitigation_plan:
    - priority: immediate
      action: Decommission and replace end-of-life XPress-DR and XPress-DR-I hardware.
      owner: IT Operations
      addresses: CVE-2026-109439
      evidence: Product reached end-of-life/end-of-support in February 2025.
---

Lantronix XPress-DR and XPress-DR-I devices utilizing the CoBos firmware family up to version 8.1.0.0 contain a critical missing authentication vulnerability (CVE-2026-109439). This flaw permits remote, unauthenticated attackers to interact with the device configuration protocol over UDP port 30718. By sending crafted frames, an attacker can extract sensitive configuration data or gain persistent unauthorized control over the device settings. Specifically, the vulnerability allows attackers to overwrite critical parameters such as the device IP address and serial-channel forwarding records. These changes are committed to the device EEPROM, ensuring persistence across reboots. Given that the XPress-DR product line reached end-of-life status in February 2025, no official security patches will be issued by the vendor to remediate this flaw.

## Impact

The vulnerability poses a severe risk of unauthorized network access and persistent device compromise. Because the device handles serial-channel forwarding, successful exploitation allows attackers to intercept or redirect serial communications, potentially leading to unauthorized control of industrial or networked equipment managed by the affected Lantronix modules. As the product is no longer supported, users must implement network-level controls to isolate these devices from untrusted network segments.

## Recommendation

* Isolate all Lantronix XPress-DR and XPress-DR-I devices from the public internet by ensuring they are not reachable via UDP port 30718 from untrusted networks.
* Configure perimeter firewalls or ACLs to restrict access to port 30718 (UDP) to only known, authorized management subnets.
* Since the affected products have reached end-of-life as of February 2025, plan for the immediate decommissioning and replacement of these devices with currently supported hardware.
