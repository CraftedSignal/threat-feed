---
title: Tenda HG10 HG7_HG9_HG10re_300001138_en_xpon Buffer Overflow Vulnerability
slug: 2026-04-tenda-hg10-bo
description: A buffer overflow vulnerability in Tenda HG10 HG7_HG9_HG10re_300001138_en_xpon allows remote attackers to execute arbitrary code by manipulating the nextHop argument in the formRoute function of the /boaform/formRouting file, impacting device availability and integrity.
date: "2026-04-25T18:18:16Z"
severities:
  - critical
tags:
  - buffer-overflow
  - cve-2026-6988
  - tenda
  - iot
vendors:
  - Tenda
products:
  - HG10 HG7_HG9_HG10re_300001138_en_xpon
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6988
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6988
  - https://github.com/xyh4ck/iot_poc/blob/main/Tenda/HG10/01_Buffer_Overflow_nextHop/README.md
  - https://vuldb.com/vuln/359540
rules:
  - title: Detect Tenda HG10 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts on Tenda HG10 devices by monitoring requests to the /boaform/formRouting endpoint with an unusually long nextHop parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG10 Boa Service Access
    description: Detects access to the Boa service on Tenda HG10 devices, which can be indicative of exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-6988, has been discovered in Tenda HG10 HG7_HG9_HG10re_300001138_en_xpon. The vulnerability resides within the Boa Service, specifically affecting the `formRoute` function located in the `/boaform/formRouting` file. Successful exploitation of this flaw enables a remote attacker to overwrite memory by crafting a malicious request with a manipulated `nextHop` argument. This can lead to arbitrary code execution on the affected device. Given…
