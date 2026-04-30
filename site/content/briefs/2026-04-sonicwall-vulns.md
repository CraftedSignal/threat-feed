---
title: Multiple Vulnerabilities in SonicWall Products Allow for DoS and Security Policy Bypass
slug: 2026-04-sonicwall-vulns
description: Multiple vulnerabilities in SonicWall firewalls could allow an attacker to cause a remote denial of service and security policy bypass, potentially disrupting network services and compromising security controls.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sonicwall
  - firewall
  - dos
  - security_bypass
vendors:
  - SonicWall
products:
  - SOHOW
  - TZ 300
  - TZ 300W
  - TZ 400
  - TZ 400W
  - TZ 500
  - TZ 500W
  - TZ 600
  - NSA 2650
  - NSA 3600
  - NSA 3650
  - NSA 4600
  - NSA 4650
  - NSA 5600
  - NSA 5650
  - NSA 6600
  - NSA 6650
  - SM 9200
  - SM 9250
  - SM 9400
  - SM 9450
  - SM 9600
  - SM 9650
  - TZ 300P
  - TZ 600P
  - SOHO 250
  - SOHO 250W
  - TZ 350
  - TZ 350W
  - TZ270
  - TZ270W
  - TZ370
  - TZ370W
  - TZ470
  - TZ470W
  - TZ570
  - TZ570W
  - TZ570P
  - TZ670
  - NSa 2700
  - NSa 3700
  - NSa 4700
  - NSa 5700
  - NSa 6700
  - NSsp 10700
  - NSsp 11700
  - NSsp 13700
  - NSsp 15700
  - NSv 270
  - NSv 470
  - NSv 870
  - NSv870 sous ESX
  - NSv870 sous KVM
  - NSv870 sous HYPER-V
  - NSv870 sous AWS
  - NSv870 sous Azure
  - TZ80
  - TZ280
  - TZ380
  - TZ480
  - TZ580
  - TZ680
  - NSa 2800
  - NSa 3800
  - NSa 4800
  - NSa 5800
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-0204
    cvss: 8
  - id: CVE-2026-0205
    cvss: 6.8
  - id: CVE-2026-0206
    cvss: 4.9
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0517/
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0004
  - https://www.cve.org/CVERecord?id=CVE-2026-0204
  - https://www.cve.org/CVERecord?id=CVE-2026-0205
  - https://www.cve.org/CVERecord?id=CVE-2026-0206
rules:
  - title: Detect Traffic to Potentially Vulnerable SonicWall Devices
    description: Detects network traffic directed towards SonicWall devices, which may indicate reconnaissance or exploitation attempts targeting the vulnerabilities described in CERTFR-2026-AVI-0517.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - network_connection
      - zeek
  - title: Detect Security Policy Bypass Attempt
    description: Detects potential attempts to bypass security policies on SonicWall devices by monitoring specific network traffic patterns.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - network_connection
      - sonicwall
rules_count: 2
---

On April 30, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting various SonicWall firewall products. These vulnerabilities, detailed in SonicWall security bulletin SNWLID-2026-0004, could allow an unauthenticated remote attacker to trigger a denial-of-service condition or bypass security policies. The affected products include a wide range of SonicWall firewalls across multiple generations (Gen 6, Gen 7, and Gen 8), as well as NSv virtual firewalls deployed in ESX, KVM, Hyper-V, AWS, and Azure environments. Successful exploitation of these vulnerabilities could lead to significant disruption of network services and a compromise of security controls.

## Attack Chain

1.  The attacker identifies a vulnerable SonicWall firewall exposed to the internet.
2.  The attacker sends a specially crafted network packet to the firewall. This packet exploits one of the vulnerabilities (CVE-2026-0204, CVE-2026-0205, or CVE-2026-0206).
3.  If the attacker exploits a DoS vulnerability, the firewall's CPU and memory resources are consumed, leading to a denial-of-service condition.
4.  Legitimate network traffic is disrupted due to the firewall's degraded performance or complete failure.
5.  If the attacker exploits a security policy bypass vulnerability, they can potentially gain unauthorized access to internal network resources.
6.  The attacker may then attempt to move laterally within the network, exploiting additional vulnerabilities in other systems.

## Impact

Successful exploitation of these vulnerabilities could lead to a complete denial of service, disrupting network connectivity for affected organizations. A security policy bypass could also allow unauthorized access to sensitive internal resources. The number of potential victims is significant, given the widespread use of SonicWall firewalls across various industries.

## Recommendation

*   Apply the patches outlined in SonicWall security bulletin SNWLID-2026-0004 to all affected SonicWall firewalls immediately.
*   Monitor network traffic for suspicious activity targeting SonicWall firewalls.
*   Deploy the Sigma rules below to your SIEM to detect potential exploitation attempts in your environment.
*   Review and enforce strict network segmentation policies to limit the impact of a potential security policy bypass.
