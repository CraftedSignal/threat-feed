---
title: Multiple Vulnerabilities in Axis Communications Products
slug: 2026-08-axis-vulnerabilities
description: Multiple security flaws, including CVE-2026-4757, CVE-2026-5303, CVE-2026-5304, CVE-2026-6181, CVE-2026-6505, and CVE-2026-8158, affect various Axis products and may lead to remote code execution, privilege escalation, or denial of service.
date: "2026-08-19T16:31:49Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Axis
products:
  - Active Track
  - Axis File Player
  - AXIS OS LTS 2024
  - Signed media verifier
  - Signed-Video-Framework
cves:
  - id: CVE-2026-4757
    cvss: 7.2
    epss: 0.0039
  - id: CVE-2026-5303
    cvss: 5.7
    epss: 0.00168
  - id: CVE-2026-5304
    cvss: 5.7
    epss: 0.00232
  - id: CVE-2026-6181
    cvss: 5.9
    epss: 0.00296
  - id: CVE-2026-6505
    cvss: 5.1
    epss: 0.00074
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1042/
  - https://www.axis.com/dam/public/41/7d/0f/cve-2026-4757pdf-en-US-543642.pdf
  - https://www.axis.com/dam/public/d5/e8/6e/cve-2026-5303pdf-en-US-543643.pdf
  - https://www.axis.com/dam/public/21/37/f2/cve-2026-5304pdf-en-US-543644.pdf
  - https://www.axis.com/dam/public/9d/8a/ea/cve-2026-6181pdf-en-US-543646.pdf
  - https://www.axis.com/dam/public/fd/16/ab/cve-2026-6505pdf-en-US-543641.pdf
  - https://www.axis.com/dam/public/6c/f3/ac/cve-2026-8158pdf-en-US-543645.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit environment for Axis products running vulnerable versions
      owner: IT Operations
      due: 24h
      evidence: System vulnerable if versions are below 12.11.44, 3.1.9.0, 11.11.207, 1.0.2, or 2.3.5.
  mitigation_plan:
    - priority: immediate
      action: Patch all vulnerable Axis devices to the latest firmware version
      owner: IT Operations
      addresses: CVE-2026-4757, CVE-2026-5303, CVE-2026-5304, CVE-2026-6181, CVE-2026-6505, CVE-2026-8158
---

On August 19, 2026, the French National Cybersecurity Agency (ANSSI) released an advisory detailing multiple security vulnerabilities affecting various Axis Communications products. These vulnerabilities, identified by CVE-2026-4757, CVE-2026-5303, CVE-2026-5304, CVE-2026-6181, CVE-2026-6505, and CVE-2026-8158, span several software components including Active Track, Axis File Player, AXIS OS LTS 2024, Signed media verifier, and the Signed-Video-Framework. If successfully exploited, these flaws could allow an unauthenticated or low-privileged remote attacker to achieve remote code execution, escalate privileges, or cause a denial of service on affected devices. Organizations utilizing Axis surveillance and security infrastructure are advised to review the vendor-provided security bulletins immediately to identify and apply the necessary patches.

## Impact

Successful exploitation of these vulnerabilities may lead to a total compromise of the affected Axis devices, enabling attackers to gain unauthorized access to camera feeds, exfiltrate sensitive data, manipulate security configurations, or render surveillance systems unavailable. Given the role of these devices in physical security, such a compromise could have significant consequences for site safety and operational integrity.

## Recommendation

Prioritize the identification of all Axis network devices within your environment and perform an audit of current firmware and software versions against the affected list. Immediately apply the patches provided by Axis Communications as detailed in the official security bulletins linked in the documentation section of the ANSSI advisory. Restrict management access to these devices to trusted subnets only to mitigate potential exploitation attempts until updates can be deployed.
