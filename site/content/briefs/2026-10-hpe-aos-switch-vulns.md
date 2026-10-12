---
title: Critical Vulnerabilities in HPE Networking AOS-Switch
slug: 2026-10-hpe-aos-switch-vulns
description: Multiple high-severity vulnerabilities in HPE Networking AOS-Switch could allow unauthenticated attackers to achieve remote code execution, perform unauthorized actions, or cause denial of service.
date: "2026-10-12T13:38:14Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - network-security
  - vulnerability-management
  - networking
  - hardware
vendors:
  - HPE
products:
  - HPE Networking AOS-Switch
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Enkele kwetsbaarheden kunnen door een aanvaller zonder account of wachtwoord misbruikt worden.
    confidence_band: high
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-hpe-networking-aos-switch-met-hoog-risico
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Patch all HPE Networking AOS-Switch devices with the latest firmware from the vendor
      owner: IT Operations
      due: 48h
      evidence: HPE Networking heeft beveiligingsupdates uitgebracht die deze kwetsbaarheden verhelpen.
  mitigation_plan:
    - priority: immediate
      action: Isolate management interfaces from the public internet and implement IP allowlisting
      owner: Network Security
      addresses: Public-facing management interfaces
      evidence: Het Nationaal Cyber Security Centrum (NCSC) adviseert om de managementinterfaces van de AOS-Switch niet direct via het internet toegankelijk te maken
---

The Netherlands National Cyber Security Centre (NCSC) has identified multiple critical vulnerabilities in HPE Networking AOS-Switch, a line of enterprise network devices used to manage and regulate data traffic. These vulnerabilities, which carry CVSS scores as high as 9.8, pose a significant risk to the integrity and availability of organizational networks. 

The flaws allow unauthenticated attackers to bypass security controls, execute arbitrary code, exfiltrate sensitive information, or trigger denial-of-service (DoS) conditions. While there is no reported in-the-wild exploitation at this time, the severity of the potential impact necessitates prompt action from network administrators. Organizations are urged to prioritize the application of vendor-supplied patches and harden device configurations by isolating management interfaces from the public internet.

## Impact

Successful exploitation could result in full device takeover, enabling attackers to intercept or modify internal network traffic, compromise credentials, or disrupt communication across the infrastructure. Given the critical role of these switches in corporate network backbones, the potential for lateral movement and broad network disruption is high. Organizations in all sectors using HPE AOS-Switch hardware are advised to audit their exposure and verify patch levels.

## Recommendation

* Apply the latest security updates provided by HPE for all affected AOS-Switch deployments immediately.
* Disable direct internet access to switch management interfaces. Restrict management access to dedicated, secure out-of-band networks.
* Implement strict IP allowlisting to ensure that only authorized administrative workstations can access the device management ports.
* Coordinate with IT service providers to audit current firmware versions and confirm the application of vendor patches.
