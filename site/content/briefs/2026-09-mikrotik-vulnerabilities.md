---
title: Multiple Vulnerabilities in MikroTik RouterOS
slug: 2026-09-mikrotik-vulnerabilities
description: Multiple vulnerabilities in MikroTik RouterOS have been identified that allow a remote, authenticated attacker to trigger a denial of service condition and manipulate arbitrary files on the device.
date: "2026-09-15T13:04:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - MikroTik
products:
  - RouterOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, authentisierter Angreifer kann mehrere Schwachstellen in MikroTik RouterOS ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3366
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict access controls for MikroTik management interfaces
      owner: IT Operations
      due: 48h
      evidence: Source notes authentication is required for exploitation
  mitigation_plan:
    - priority: immediate
      action: Monitor for firmware updates from MikroTik
      owner: IT Operations
      addresses: RouterOS vulnerabilities
      evidence: Source identifies vulnerabilities in RouterOS
---

The German Federal Office for Information Security (BSI) has reported multiple security vulnerabilities affecting MikroTik RouterOS. These vulnerabilities reside within the core router operating system and can be leveraged by a remote attacker who has already successfully authenticated to the device. Exploitation of these flaws allows for the disruption of network services through a denial-of-service (DoS) condition, as well as the unauthorized manipulation of files residing on the router's file system. Because these vulnerabilities require prior authentication, they represent a significant risk for environments where administrative credentials have been compromised or where low-privileged user accounts have excessive access rights within the router management interface. Defenders should prioritize auditing user account permissions and restricting management interface access to trusted networks.

## Impact

Successful exploitation of these vulnerabilities allows for the disruption of network infrastructure through device-level denial-of-service and grants an attacker the ability to modify system files, potentially leading to further compromise of the device's configuration or persistence. Organizations relying on MikroTik devices for critical routing and firewall functionality are at risk of operational downtime and potential security configuration tampering.

## Recommendation

- Perform an immediate audit of all user accounts with access to the MikroTik RouterOS web or command-line interface.
- Restrict access to the router management interfaces to dedicated, isolated management networks or VPNs.
- Monitor router logs for unauthorized file modification events or unexpected device reboots.
- Review vendor support channels for available security patches and firmware updates to address these identified vulnerabilities.
