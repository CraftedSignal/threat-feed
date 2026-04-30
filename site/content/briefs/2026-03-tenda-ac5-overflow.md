---
title: Tenda AC5 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ac5-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-4905) exists in Tenda AC5 firmware version 15.03.06.47 allowing remote attackers to execute arbitrary code by manipulating the 'index' argument in a POST request to the /goform/WifiWpsOOB endpoint.
date: "2026-03-27T00:16:24Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - tenda
  - router
  - cve-2026-4905
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4905
  - https://lavender-bicycle-a5a.notion.site/Tenda_AC5_WifiWpsOOB_index-32053a41781f8096a9b6e48177c25eb0?source=copy_link
  - https://vuldb.com/?id.353656
rules:
  - title: Tenda AC5 WifiWpsOOB Buffer Overflow Attempt
    description: Detects suspicious HTTP POST requests to the WifiWpsOOB endpoint with an excessively long index parameter, indicating a potential buffer overflow attempt (CVE-2026-4905).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Tenda AC5 WifiWpsOOB POST Request Anomaly
    description: Detects abnormal POST requests to the Tenda AC5 WifiWpsOOB endpoint based on content length
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-4905, has been discovered in Tenda AC5 home routers running firmware version 15.03.06.47. The vulnerability resides within the `formWifiWpsOOB` function in the `/goform/WifiWpsOOB` file, which handles POST requests. Attackers can remotely exploit this flaw by crafting a malicious POST request to this endpoint, specifically targeting the `index` argument. Successful exploitation leads to arbitrary code execution on the device…
