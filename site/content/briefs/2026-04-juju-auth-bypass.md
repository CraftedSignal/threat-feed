---
title: Juju CloudSpec API Authorization Bypass (CVE-2026-5412)
slug: 2026-04-juju-auth-bypass
description: CVE-2026-5412 describes an authorization issue in Juju versions prior to 2.9.57 and 3.6.21, where a low-privileged authenticated user can call the CloudSpec API method to extract cloud credentials used to bootstrap the controller, leading to sensitive credential exposure.
date: "2026-04-10T13:16:45Z"
severities:
  - critical
tags:
  - vulnerability
  - authorization
  - cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-5412
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5412
ioc_counts:
  email: 1
rules:
  - title: Detect Juju CloudSpec API Access
    description: Detects unauthorized access to the Juju CloudSpec API endpoint, indicating a potential attempt to exploit CVE-2026-5412.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Juju API Request with Suspicious User Agent
    description: Detects Juju API requests with unusual user agents, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5412 identifies an authorization bypass vulnerability affecting Juju, an open-source service orchestration tool. Specifically, versions prior to 2.9.57 and 3.6.21 are susceptible. An authenticated user with low privileges can exploit this vulnerability by invoking the CloudSpec API method. This method, intended for controller bootstrapping, inadvertently exposes sensitive cloud credentials when accessed by unauthorized users. Successful exploitation grants access to the credentials…
