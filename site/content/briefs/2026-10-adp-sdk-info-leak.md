---
title: Clear Text Transmission Vulnerability in ADP Desktop SDK
slug: 2026-10-adp-sdk-info-leak
description: The ADP Desktop SDK improperly transmits sensitive information in clear text, allowing local network attackers to intercept credentials and gain unauthorized access to Autodesk services.
date: "2026-10-14T18:43:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:autodesk:adp_desktop_sdk:*:*:*:*:*:*:*:*
vendors:
  - Autodesk
products:
  - ADP Desktop SDK
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Exploitation of this vulnerability can lead to unauthorized access to Autodesk services.
    confidence_band: high
cves:
  - id: CVE-2026-15102
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15102
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and inventory all deployed software utilizing the ADP Desktop SDK
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-15102 affecting ADP Desktop SDK
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply security patches provided by Autodesk to resolve CVE-2026-15102
      owner: IT Operations
      addresses: CVE-2026-15102
      evidence: NVD vulnerability disclosure
  gaps:
    - Lack of specific network-based IOCs for immediate detection
---

The Autodesk ADP Desktop SDK contains a critical information exposure vulnerability categorized under CVE-2026-15102. The software fails to implement adequate encryption for sensitive data transmissions during its standard operation. This allows an attacker with a position on the local network to perform passive sniffing or man-in-the-middle attacks to intercept sensitive information, including authentication tokens or credentials. If successfully exploited, an adversary can gain unauthorized access to an organization's Autodesk account or cloud-based services, potentially leading to unauthorized data access or project modification. The vulnerability affects the SDK across both Windows and macOS platforms. Organizations using software integrated with the ADP Desktop SDK should audit current versions and monitor for updates from Autodesk to remediate this communication flaw.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to compromise user credentials and session identifiers. This leads to unauthorized access to the victim's Autodesk environment, risking the exposure of proprietary designs, intellectual property, or project data hosted within the Autodesk ecosystem. The risk is particularly high for environments where developers or engineers frequently interact with cloud-based Autodesk services over shared or untrusted local networks.

## Recommendation

* Monitor official Autodesk security bulletins for patch releases addressing CVE-2026-15102 and update all software utilizing the ADP Desktop SDK immediately upon availability.
* Enforce the use of encrypted VPN tunnels or host-based firewalls to restrict local network traffic originating from workstations running Autodesk software until the vulnerability is patched.
* Audit network traffic patterns from developer workstations to identify unauthorized clear-text communication on non-standard ports typically associated with SDK telemetry or service authentication.
