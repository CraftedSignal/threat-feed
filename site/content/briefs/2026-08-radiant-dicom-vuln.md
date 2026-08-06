---
title: Medixant RadiAnt DICOM Out-of-Bounds Write Vulnerability
slug: 2026-08-radiant-dicom-vuln
description: Medixant RadiAnt DICOM versions 2025.2 and earlier are vulnerable to a heap out-of-bounds write flaw that may lead to arbitrary code execution when processing maliciously crafted DICOM files.
date: "2026-08-06T17:31:19Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
vendors:
  - Medixant
products:
  - RadiAnt DICOM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Opening a crafted DICOM file containing malicious JPEG-compressed pixel data triggers an attacker-controlled heap out-of-bounds write.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-218-01
  - https://www.cve.org/CVERecord?id=CVE-2026-17264
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade RadiAnt DICOM to version 2026.1
      owner: IT Operations
      due: 72h
      evidence: Remediation guidance in CISA advisory
---

Medixant RadiAnt DICOM is a medical imaging software widely used within the Healthcare and Public Health sector for viewing DICOM files. A vulnerability, identified as CVE-2026-17264, exists in versions 2025.2 and earlier of the application. The flaw is caused by improper handling of JPEG-compressed pixel data within a DICOM file, leading to a heap out-of-bounds write (CWE-787). An attacker can leverage this by delivering a specially crafted file to a user. While the software employs modern exploit mitigations like Control Flow Guard (CFG), Data Execution Prevention (DEP), and Address Space Layout Randomization (ASLR), successful exploitation remains a risk, potentially resulting in application crashes or remote code execution. This vulnerability is significant for clinical environments where the integrity and availability of diagnostic imaging software are paramount.

## Impact

The vulnerability affects the Healthcare and Public Health sector globally. If successfully exploited, an attacker could force the application to crash, disrupting medical diagnostic workflows, or potentially gain arbitrary code execution on the workstation where the DICOM file is opened. There are no reports of active exploitation in the wild as of August 2026.

## Recommendation

* Update Medixant RadiAnt DICOM to version 2026.1 immediately to patch CVE-2026-17264.
* Enforce a policy to open DICOM files only from trusted and verified sources to reduce the risk of handling malicious content.
* Minimize network exposure for workstations running medical imaging software by isolating them from general business networks and the internet.
