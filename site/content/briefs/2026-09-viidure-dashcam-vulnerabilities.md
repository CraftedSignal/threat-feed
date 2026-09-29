---
title: Critical Vulnerabilities in Viidure Dashcam Android Application
slug: 2026-09-viidure-dashcam-vulnerabilities
description: The Viidure Dashcam Android application (<= 3.3.1.260403) contains two high-risk vulnerabilities, including hard-coded cloud credentials and misconfigured public cloud storage, that expose sensitive user data and platform firmware.
date: "2026-09-29T16:25:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - iot
  - mobile-app
  - cve
  - transportation
vendors:
  - Viidure
products:
  - Viidure Dashcam Android Application (<= 3.3.1.260403)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The Viidure Android application embeds permanent, plaintext cloud storage credentials within its compiled code.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The central cloud storage backend for the entire dashcam platform is misconfigured with public-read permissions, allowing unrestricted access to all stored objects.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-07
  - https://www.cve.org/CVERecord?id=CVE-2026-94204
  - https://www.cve.org/CVERecord?id=CVE-2026-96587
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate devices running the affected application from business networks
      owner: IT Operations
      due: 24h
      evidence: CISA recommendation to locate remote devices behind firewalls and isolate them from business networks
  mitigation_plan:
    - priority: immediate
      action: Monitor for or block access to the cloud storage backends utilized by the Viidure platform
      owner: SOC
      addresses: CVE-2026-94204
      evidence: Backend cloud storage is misconfigured with public-read permissions
---

The Viidure Dashcam Android application, used globally in the transportation sector, contains two critical security flaws identified as CVE-2026-94204 and CVE-2026-96587. The vulnerabilities originate from a combination of poor development practices and backend misconfiguration. Specifically, the application embeds hard-coded, plaintext cloud storage credentials within its compiled binaries (CVE-2026-96587), providing attackers with full read, write, and delete capabilities over the platform's cloud storage. Furthermore, the associated backend storage is misconfigured with public-read permissions (CVE-2026-94204), leading to the exposure of private user records, live dashcam footage, and critical firmware files. These vulnerabilities pose a significant threat to user privacy and system integrity, potentially allowing attackers to compromise the entire dashcam ecosystem. The vendor, Viidure, has not responded to coordination attempts, and no fixes are currently planned for the affected versions.

## Impact

The impact of these vulnerabilities is substantial, as they expose private user information, including live footage from dashcams, to unauthorized actors globally. Successful exploitation allows for the modification or deletion of platform-critical files, such as firmware, which could lead to mass service disruption or the injection of malicious updates across the user base. As the platform is used worldwide in transportation systems, the risks include widespread privacy violations and the potential for large-scale operational sabotage.

## Recommendation

Prioritized, concrete actions for organizations using the Viidure platform:

* Immediately restrict all network access to Viidure cloud resources if integrated into corporate environments, as no vendor patch is available.
* Evaluate organizational risk regarding the usage of this application, given the lack of a vendor-provided remediation plan.
* Isolate any mobile devices running the Viidure Dashcam application from sensitive enterprise networks and implement strict egress filtering to prevent unauthorized data exfiltration to the identified cloud storage backends.
* Consult the vendor at https://viidure.app/ for any potential updates or guidance, though no official fix is currently available.
