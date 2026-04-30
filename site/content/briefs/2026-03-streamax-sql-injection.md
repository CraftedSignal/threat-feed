---
title: Shenzhen Ruiming Technology Streamax Crocus bis SQL Injection Vulnerability
slug: 2026-03-streamax-sql-injection
description: A SQL injection vulnerability (CVE-2026-4910) exists in Shenzhen Ruiming Technology Streamax Crocus bis 1.3.44 via the /RemoteFormat.do endpoint, allowing remote attackers to execute arbitrary SQL commands by manipulating the State argument.
date: "2026-03-27T04:16:08Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4910
  - sql-injection
  - streamax
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4910
  - https://my.feishu.cn/docx/QZU6dXZBBoBeLMx4K28cW1BEnsZ?from=from_copylink
  - https://vuldb.com/?ctiid.353661
  - https://vuldb.com/?id.353661
  - https://vuldb.com/?submit.777507
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect SQL Injection Attempt in Streamax RemoteFormat.do
    description: Detects potential SQL injection attempts targeting the /RemoteFormat.do endpoint by looking for SQL keywords in the State parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Streamax RemoteFormat.do Endpoint
    description: Detects access to the Streamax RemoteFormat.do endpoint which might indicate reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-4910, affects Shenzhen Ruiming Technology Streamax Crocus bis version 1.3.44. The vulnerability is located within the `/RemoteFormat.do` file, specifically the `Endpoint` component. By manipulating the `State` argument, a remote attacker can inject arbitrary SQL commands. Publicly available exploits exist, increasing the risk of exploitation. The vendor was notified but did not respond. Successful exploitation could lead to unauthorized data…
