---
title: Multiple Vulnerabilities in Botslab G980H Dashcams
slug: 2026-09-botslab-dashcam-vulnerabilities
description: Botslab G980H dash cameras are impacted by 14 firmware vulnerabilities allowing unauthenticated adjacent network attackers to bypass authentication, hijack sessions, and gain full control over device functionality.
date: "2026-09-24T16:14:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - firmware-vulnerability
  - transportation
vendors:
  - Botslab
products:
  - G980H Dashcams (30010_QHG980HN5294SysFW+)
  - G980H Dashcams (58_QHG980HMCN5291SysFW+)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with adjacent network access could potentially use valid session state associated with another client to access privileged functionality.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated attacker with adjacent network access who captures a valid authentication value could replay it from another client to establish an authenticated session.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-267-01
  - https://www.cve.org/CVERecord?id=CVE-2026-84399
  - https://www.cve.org/CVERecord?id=CVE-2026-82566
  - https://www.cve.org/CVERecord?id=CVE-2026-85496
  - https://www.cve.org/CVERecord?id=CVE-2026-77967
  - https://www.cve.org/CVERecord?id=CVE-2026-88761
  - https://www.cve.org/CVERecord?id=CVE-2026-82716
  - https://www.cve.org/CVERecord?id=CVE-2026-84403
  - https://www.cve.org/CVERecord?id=CVE-2026-75558
  - https://www.cve.org/CVERecord?id=CVE-2026-81630
  - https://www.cve.org/CVERecord?id=CVE-2026-87118
  - https://www.cve.org/CVERecord?id=CVE-2026-82708
  - https://www.cve.org/CVERecord?id=CVE-2026-79959
  - https://www.cve.org/CVERecord?id=CVE-2026-82585
  - https://www.cve.org/CVERecord?id=CVE-2026-88956
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate Botslab G980H Dashcams from internet-facing and untrusted subnets
      owner: IT Operations
      due: 24h
      evidence: High CVSS 8.8 rating indicating severe risk of unauthorized access
  mitigation_plan:
    - priority: immediate
      action: Remove device from production network until vendor provides security patches
      owner: IT Operations
      addresses: All listed CVEs
      evidence: No vendor response or mitigation currently available
---

Botslab G980H dash cameras (versions 30010_QHG980HN5294SysFW+ and 58_QHG980HMCN5291SysFW+) are impacted by a significant set of 14 vulnerabilities, including CVE-2026-84399, CVE-2026-82566, CVE-2026-85496, CVE-2026-77967, CVE-2026-88761, CVE-2026-82716, CVE-2026-84403, CVE-2026-75558, CVE-2026-81630, CVE-2026-87118, CVE-2026-82708, CVE-2026-79959, CVE-2026-82585, and CVE-2026-88956. These flaws stem from poor implementation of authorization and session management within the firmware. 

Defenders should note that the vendor has not provided patches for these issues. The vulnerabilities allow an unauthenticated attacker located on an adjacent network to intercept sessions, guess session identifiers, or replay authentication tokens to execute unauthorized commands. The scope of impact is broad, potentially affecting any transportation sector organization using these specific camera models globally. Because these devices serve as sensitive recording equipment, successful exploitation poses a severe risk to both operational privacy and device integrity.

## Impact

Successful exploitation allows an attacker to bypass authentication, access sensitive captured data, modify device configurations, and disrupt device operation. These vulnerabilities affect the Transportation Systems critical infrastructure sector globally. Given the lack of vendor response or remediation, affected devices currently remain in an unpatched, vulnerable state.

## Recommendation

* Immediately isolate Botslab G980H dash cameras from public-facing or untrusted adjacent networks to prevent unauthorized remote access.
* Implement strict network segmentation to ensure these devices cannot communicate with unauthorized endpoints.
* Monitor network traffic originating from or destined to Botslab G980H hardware for anomalous authentication patterns or unauthorized API requests.
* Contact Botslab directly for updates regarding the availability of firmware patches as no official mitigation or update currently exists.
