---
brief_id: brief-2026-11-02-attendo-android-credentials
event_id: brief-2026-11-02-attendo-android-credentials
revision: 1
activity_at: "2026-11-02T19:48:28Z"
title: 'Attendo Admin Android Application: Hard-coded MQTT Broker Credentials (CVE-2026-119736)'
slug: 2026-11-attendo-android-credentials
description: The Attendo Admin Android application version 3.0.13 and earlier contains hard-coded MQTT credentials in bundled configuration files, allowing unauthorized access to production data and potential message injection.
date: "2026-11-02T19:48:28Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: No detection artifacts available for mobile app binaries in a standard SIEM; hunting and mitigation prioritized.
cpes:
  - cpe:2.3:a:attendo:admin:*:*:*:*:*:android:*:*
tags:
  - mobile-security
  - android
  - vulnerability
  - mqtt
  - information-disclosure
vendors:
  - Attendo
products:
  - Attendo Admin Android application (<= 3.0.13)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Attackers can use the recovered credentials to authenticate to the production MQTT broker over TCP 1883.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attacker can decompile the APK to extract MQTT broker credentials from bundled Flutter configuration files (e.g., production.json).
    confidence_band: high
cves:
  - id: CVE-2026-119736
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119736
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and flag devices running Attendo Admin application version 3.0.13 or earlier
      owner: IT Operations
      due: 48h
      evidence: Vulnerability in version 3.0.13 and earlier
  hunt_leads:
    - lead: Monitor network traffic for unauthorized clients initiating connections to the production MQTT broker on TCP 1883
      technique_id: T1552.001
      data_needed:
        - Firewall or MQTT broker access logs (SourceIp, DestinationPort, User)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can use the recovered credentials to authenticate to the production MQTT broker over TCP 1883.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched version of Attendo Admin once available
      owner: IT Operations
      addresses: CVE-2026-119736
      evidence: Hard-coded credentials vulnerability in version 3.0.13 and earlier
---

The Attendo (formerly Petpooja Payroll) Admin Android application, versions 3.0.13 and earlier, contains hard-coded credentials for a production MQTT broker. These credentials are embedded within Flutter configuration assets, specifically in files such as production.json and device-command configuration files. Unauthorized parties can extract these credentials by decompiling the APK file.

## Impact
Successful exploitation allows an attacker to authenticate to the production MQTT broker over TCP 1883. Access enables the retrieval of sensitive data from messaging topics, including employee attendance records, personal identifiers, Base64-encoded photographs, and device telemetry. Furthermore, attackers can publish messages to these topics, facilitating unauthorized message injection.

## Recommendation
- Inventory all mobile devices within the corporate environment running the Attendo Admin application.
- Upgrade the Attendo Admin Android application to a version released after 3.0.13 once a patch is provided by the vendor.
- Implement network-level monitoring or restrictions on outbound connections to the MQTT broker (TCP 1883) from non-authorized devices.
