---
title: Multiple Vulnerabilities in Bransys ELD Affecting Data Privacy
slug: 2026-09-bransys-eld-vulnerabilities
description: Bransys ELD versions for Android and iOS contain hard-coded credentials and cleartext transmission flaws, allowing unauthorized read access to real-time telemetry data.
date: "2026-09-17T18:10:58Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ics
  - transportation
  - data-privacy
  - cve-2026-86520
  - cve-2026-86689
  - cve-2026-77960
vendors:
  - Bransys
products:
  - Bransys ELD (Android < 11.00.00)
  - Bransys ELD (iOS < 1.1.54)
affected_os:
  - Android
  - iOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The affected product is shipped with hardcoded MQTT/FTP credentials.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-01
  - https://www.cve.org/CVERecord?id=CVE-2026-86520
  - https://www.cve.org/CVERecord?id=CVE-2026-86689
  - https://www.cve.org/CVERecord?id=CVE-2026-77960
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update all instances of Bransys ELD to Android v11.00.00 or iOS v1.1.54
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation guidance in ICSA-26-260-01
  mitigation_plan:
    - priority: immediate
      action: Isolate fleet ELD network communication behind firewalls and VPNs
      owner: IT Operations
      addresses: CVE-2026-86520, CVE-2026-86689, CVE-2026-77960
      evidence: Recommended practices in CISA advisory
---

Bransys has disclosed multiple vulnerabilities in the Bransys ELD mobile application affecting Android versions prior to 11.00.00 and iOS versions prior to 1.1.54. These vulnerabilities include the use of hard-coded credentials for MQTT (CVE-2026-86520) and FTP (CVE-2026-77960) services, as well as the cleartext transmission of sensitive information (CVE-2026-86689). An attacker with network access to the target broker or server could leverage these credentials to gain unauthorized read access to real-time device telemetry data across a subset of carriers. These flaws represent significant privacy and security risks for transportation systems in the United States where these devices are deployed. There is currently no evidence of active exploitation in the wild.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized parties to access sensitive real-time telemetry data and potentially other device information. Given the deployment of these systems in the transportation sector, unauthorized access to fleet data and device information poses operational and privacy risks to the involved carriers.

## Recommendation

* Update Bransys ELD to the latest available versions: Android v11.00.00 or higher and iOS v1.1.54 or higher via official app stores.
* Restrict network access to telemetry servers and brokers; ensure these devices are isolated behind firewalls and not directly exposed to the internet.
* Monitor for unauthorized connection attempts or unusual traffic patterns originating from fleet mobile devices toward MQTT or FTP infrastructure.
