---
title: Unrestricted File Upload in SourceCodester E-Learning System
slug: 2026-10-sourcecodester-e-learning-upload
description: SourceCodester E-Learning System 1.0 contains an unrestricted file upload vulnerability in the save_users function, allowing remote attackers to upload arbitrary files to the server.
date: "2026-10-13T08:33:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:e-learning_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - remote-code-execution
  - file-upload
vendors:
  - SourceCodester
products:
  - E-Learning System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-108974
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108974
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all web servers to locate instances of SourceCodester E-Learning System
      owner: SOC
      due: 24h
      evidence: CVE-2026-108974 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the /classes/Users.php endpoint until the product can be updated or removed
      owner: IT Operations
      addresses: CVE-2026-108974
      evidence: NVD vulnerability details
---

A security vulnerability identified as CVE-2026-108974 exists in the SourceCodester E-Learning System version 1.0. The flaw resides in the 'save_users' function located within '/classes/Users.php'. An unauthenticated or authenticated remote attacker can manipulate the 'img' argument during a file upload process to bypass restrictions, resulting in the ability to upload arbitrary files to the web server. This vulnerability is significant because a publicly available exploit exists, lowering the barrier for entry for potential attackers. If exploited, an attacker could upload malicious scripts, such as web shells, to achieve remote code execution on the underlying host, leading to full system compromise.

## Impact

Successful exploitation of this vulnerability allows for arbitrary file upload, which is a precursor to full application takeover. In an educational environment, this could lead to the exposure of student and faculty records, unauthorized access to administrative functions, or the use of the server as a pivot point for lateral movement within the network.

## Recommendation

Prioritize the identification and isolation of any instances of SourceCodester E-Learning System 1.0 within the environment. If the software is in use, verify if patches or vendor updates are available, or restrict access to the application via network-level controls until a secure configuration or update is applied.
