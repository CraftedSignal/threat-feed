---
title: Stormshield Network Security (SNS) Remote Denial-of-Service Vulnerability
slug: 2026-05-stormshield-dos
description: A remote denial-of-service vulnerability exists in Stormshield Network Security (SNS) versions 4.3.x before 4.3.43, 4.4.x to 4.8.x before 4.8.16, and 5.x before 5.0.6, allowing an attacker to disrupt service availability.
date: "2026-05-22T13:06:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - network-security
  - cve-2025-9086
vendors:
  - Stormshield
products:
  - Network Security (SNS) 4.3.x
  - Network Security (SNS) 4.4.x
  - Network Security (SNS) 4.8.x
  - Network Security (SNS) 5.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2025-9086
    cvss: 7.5
    epss: 0.00062
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0631/
  - https://advisories.stormshield.eu/2026-010
  - https://www.cve.org/CVERecord?id=CVE-2025-9086
rules:
  - title: Detects CVE-2025-9086 Exploitation Attempt - Suspicious Network Traffic to SNS
    description: Detects CVE-2025-9086 exploitation attempt - monitors network traffic for specific patterns indicative of exploitation attempts against Stormshield SNS devices. This requires tuning based on internal network configuration.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detects CVE-2025-9086 Exploitation Attempt - Potential DoS Activity
    description: Detects CVE-2025-9086 exploitation attempt - monitors for a high volume of connections to a Stormshield SNS device, which could indicate a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability has been discovered in Stormshield Network Security (SNS) that allows an attacker to cause a remote denial of service. The vulnerability affects SNS versions 4.3.x prior to 4.3.43, SNS versions 4.4.x to 4.8.x prior to 4.8.16, and SNS versions 5.x prior to 5.0.6. An attacker exploiting this vulnerability can disrupt the availability of the affected SNS devices, potentially impacting network security and accessibility. The vulnerability is identified as CVE-2025-9086 and is detailed in StormShield security bulletin 2026-010. This poses a significant threat to organizations relying on Stormshield SNS for network security, requiring immediate patching.

## Attack Chain

1.  Attacker identifies a vulnerable Stormshield Network Security (SNS) device running an affected version (4.3.x before 4.3.43, 4.4.x to 4.8.x before 4.8.16, or 5.x before 5.0.6).
2.  Attacker crafts a malicious network packet specifically designed to exploit CVE-2025-9086. The specific details of the packet structure are not publicly available but target a known vulnerability.
3.  Attacker sends the crafted packet to the vulnerable SNS device over the network.
4.  The SNS device receives and processes the malicious packet.
5.  Due to the vulnerability, processing of the packet causes the SNS device to enter a denial-of-service state. This may involve crashing the device, exhausting its resources, or causing it to become unresponsive.
6.  The SNS device becomes unavailable, disrupting network traffic and security services it provides.
7.  Legitimate users are unable to access network resources protected by the affected SNS device.

## Impact

Successful exploitation of CVE-2025-9086 results in a denial-of-service condition on the Stormshield Network Security (SNS) device. This can lead to network outages, disruptions in service availability, and potential exposure of internal network resources. The impact depends on the role of the SNS device within the network infrastructure, but can range from localized service interruptions to widespread network failures. Organizations relying on SNS for critical security functions are particularly vulnerable.

## Recommendation

*   Immediately patch Stormshield Network Security (SNS) devices to the latest versions to address CVE-2025-9086, as detailed in StormShield security bulletin 2026-010.
*   Monitor network traffic for suspicious packets targeting Stormshield SNS devices. Tuning and deployment of the provided network connection rule can detect potential exploitation attempts.
*   Review and update incident response plans to include procedures for addressing denial-of-service attacks targeting network security devices.
*   Apply the provided Sigma rule for process creation to detect potential exploitation attempts on vulnerable systems.
*   Consult the Stormshield advisory (https://advisories.stormshield.eu/2026-010) for detailed patching instructions and mitigation guidance.
