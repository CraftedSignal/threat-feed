---
title: Improper Authorization Vulnerability in Lenovo File Manager Android App
slug: 2026-09-lenovo-file-manager-vuln
description: A local improper authorization vulnerability in the Lenovo File Manager Android app allows authenticated local users to read or modify protected application files.
date: "2026-09-10T23:10:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lenovo:file_manager:*:*:*:*:*:android:*:*
tags:
  - vulnerability
  - android
  - privilege-escalation
vendors:
  - Lenovo
products:
  - File Manager (Chinese market distribution)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A potential improper authorization vulnerability was reported in the Lenovo File Manager Android App that could allow a local authenticated user to read or modify protected files.
    confidence_band: high
cves:
  - id: CVE-2026-18994
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18994
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all mobile devices to identify the presence of Lenovo File Manager.
      owner: IT Operations
      due: 48h
      evidence: Source identification of affected vendor/product.
  mitigation_plan:
    - priority: medium_term
      action: Remove or update the application if official patches are released for the identified Chinese market version.
      owner: IT Operations
      addresses: CVE-2026-18994
      evidence: NVD vulnerability disclosure.
---

An improper authorization vulnerability (CVE-2026-18994) has been identified in the Lenovo File Manager Android application. This vulnerability is specific to the version of the application distributed within the Chinese market. It allows a local, authenticated user to bypass existing authorization controls, granting them the ability to read or modify protected files maintained by the application. This could lead to unauthorized data exposure or manipulation of sensitive user data stored within the app's directory. Defenders should note that this is a local attack vector requiring the adversary to have already gained access to the mobile device or have an application running with sufficient permissions to interface with the Lenovo File Manager.

## Impact

The vulnerability affects the Lenovo File Manager application distributed in the Chinese market. Successful exploitation allows a local user to gain unauthorized access to protected file resources, potentially resulting in data exfiltration or corruption. The CVSS base score for this vulnerability is 7.1.

## Recommendation

Prioritize the identification of Lenovo File Manager installations on mobile devices managed within the organization. Check for updates provided via the official vendor channels for the Chinese market and apply patches immediately. As this is a local privilege escalation vector, audit Android permissions and ensure that only trusted applications are installed on devices that have access to corporate data.
