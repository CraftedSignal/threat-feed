---
title: Rockwell Automation CompactLogix and ControlLogix Vulnerabilities Lead to Denial-of-Service
slug: 2026-07-rockwell-automation-ics-dos
description: Multiple Rockwell Automation CompactLogix, ControlLogix, Compact GuardLogix, and GuardLogix product versions are vulnerable to denial-of-service conditions through CVE-2025-12011, CVE-2025-12012, and CVE-2025-11698, which an attacker can exploit via buffer overflows by loading invalid project files or writing invalid data, causing controllers to enter a major non-recoverable fault.
date: "2026-07-16T16:09:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - scada
  - denial-of-service
  - critical-manufacturing
  - vulnerability
vendors:
  - Rockwell Automation
products:
  - CompactLogix 5370
  - Compact GuardLogix 5370
  - ControlLogix 5570
  - GuardLogix 5570
  - CompactLogix 5380
  - Compact GuardLogix 5380
  - CompactLogix 5480
  - ControlLogix 5580
  - GuardLogix 5580
  - CompactLogix 5380 Recovery Image
  - Compact GuardLogix 5380 Recovery Image
  - CompactLogix 5480 Recovery Image
  - ControlLogix 5580 Recovery Image
  - GuardLogix 5580 Recovery Image
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Firmware Corruption
    evidence: Successful exploitation of these vulnerabilities could allow an attacker to cause a denial-of-service condition... causing the device to enter a major non-recoverable fault (MNRF).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Firmware Corruption
    evidence: A denial-of-service issue exists... This vulnerability could potentially allow a remote user to load an invalid project, causing the device to enter a major non-recoverable fault (MNRF).
    confidence_band: high
cves:
  - id: CVE-2025-12011
    epss: 0.00253
  - id: CVE-2025-12012
    epss: 0.00253
  - id: CVE-2025-11698
    epss: 0.00253
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-06
  - https://www.cve.org/CVERecord?id=CVE-2025-12011
  - https://www.cve.org/CVERecord?id=CVE-2025-12012
  - https://www.cve.org/CVERecord?id=CVE-2025-11698
---

CISA has released an advisory detailing critical denial-of-service (DoS) vulnerabilities (CVE-2025-12011, CVE-2025-12012, CVE-2025-11698) affecting numerous Rockwell Automation CompactLogix, ControlLogix, Compact GuardLogix, and GuardLogix controllers and their recovery images. These vulnerabilities, identified as buffer overflows (CWE-120), allow a remote malicious user to trigger a Major Non-Recoverable Fault (MNRF) by introducing specially crafted invalid project data or files. The affected products are widely deployed in Critical Manufacturing sectors globally. Successful exploitation can halt industrial processes, leading to significant operational disruption. Affected versions include CompactLogix 5370 <=V35.015, ControlLogix 5570 <=V35.015, CompactLogix 5380 <=V35.011, ControlLogix 5580 <=V35.011, and various associated recovery images <=1.072.

## Attack Chain

1. An attacker gains network access to the targeted Rockwell Automation CompactLogix, ControlLogix, Compact GuardLogix, or GuardLogix controller.
2. The attacker crafts a malicious project file or invalid file data designed to trigger a buffer overflow.
3. The attacker transmits the crafted invalid project file to the controller for loading (CVE-2025-12011).
4. Alternatively, the attacker writes the invalid file data to the controller (CVE-2025-12012).
5. The vulnerable controller attempts to process the malformed input, leading to a buffer overflow condition (CWE-120).
6. The buffer overflow corrupts the controller's memory or state.
7. The controller enters a Major Non-Recoverable Fault (MNRF) state.
8. The controller ceases normal operation, resulting in a denial-of-service condition for the controlled industrial process.

## Impact

Successful exploitation of these vulnerabilities leads directly to a denial-of-service condition within Rockwell Automation industrial control systems. When a controller enters a Major Non-Recoverable Fault (MNRF), it ceases operation, which can bring critical industrial processes to a halt. This directly impacts operational technology (OT) environments, potentially causing production downtime, equipment damage, safety hazards, and significant financial losses for organizations within Critical Manufacturing sectors worldwide. Given the widespread deployment of these controllers, a successful attack could have broad implications for industrial stability and supply chains.

## Recommendation

* Patch CVE-2025-12011, CVE-2025-12012, and CVE-2025-11698 by updating affected Rockwell Automation products to the recommended fixed versions immediately.
* For CompactLogix 5370, Compact GuardLogix 5370, ControlLogix 5570, and GuardLogix 5570, update to V35.016, V36.011, or later.
* For CompactLogix 5380, Compact GuardLogix 5380, CompactLogix 5480, ControlLogix 5580, and GuardLogix 5580, update to V34.014, V35.013, V36.011, or later.
* For Recovery Images, update to boot firmware 1.072 or greater; versions V36.013, V37.011, and later already include the corrected boot firmware.
