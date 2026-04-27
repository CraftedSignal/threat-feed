---
title: ZTE ZXEDM iEMS Password Reset Vulnerability (CVE-2026-40436)
slug: 2026-04-zte-zxedm-password-reset
description: CVE-2026-40436 is a vulnerability in the ZTE ZXEDM iEMS product that allows attackers to reset user passwords due to improper access control on the user list acquisition function within the cloud EMS portal, potentially leading to unauthorized operations and system compromise.
date: "2026-04-13T07:16:50Z"
severities:
  - high
tags:
  - cve
  - password-reset
  - zte
  - zxedm
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-40436
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40436
  - https://support.zte.com.cn/zte-iccp-isupport-webui/support/bulletin/security?lang=en_US&t=0.7465962531829456
rules:
  - title: Detect Account Password Reset Activity
    description: Detects unusual password reset activity that may indicate exploitation of CVE-2026-40436
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - webserver
      - linux
  - title: Detect User List Access Attempt
    description: Detects attempts to access the user list interface without proper authorization, potentially indicative of CVE-2026-40436 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-40436 is a critical vulnerability affecting ZTE ZXEDM iEMS, a cloud EMS portal, disclosed in April 2026. The vulnerability arises from inadequate access control within the user list acquisition function. An attacker, with low-level privileges (i.e., access to the cloud EMS portal), can exploit this flaw to retrieve a comprehensive list of all users managed by the system. Subsequently, leveraging the obtained user information, the attacker can reset passwords for targeted accounts…
