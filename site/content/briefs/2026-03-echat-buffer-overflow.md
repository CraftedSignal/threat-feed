---
title: EChat Server 3.1 Buffer Overflow Vulnerability in chat.ghp Endpoint
slug: 2026-03-echat-buffer-overflow
description: EChat Server 3.1 is vulnerable to a buffer overflow in the chat.ghp endpoint, allowing remote attackers to execute arbitrary code by sending a crafted GET request with an oversized username parameter.
date: "2026-03-28T12:16:02Z"
severities:
  - critical
tags:
  - buffer-overflow
  - code-execution
  - echat
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25221
  - https://www.exploit-db.com/exploits/44155
  - https://www.vulncheck.com/advisories/echat-server-buffer-overflow-via-chat-ghp-username-parameter
rules:
  - title: Detect Suspiciously Long GET Requests to chat.ghp
    description: Detects abnormally long GET requests to the chat.ghp endpoint, which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect chat.ghp access with unusual user agents
    description: Detects requests to chat.ghp with user agents other than standard browsers
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

EChat Server 3.1 is susceptible to a critical buffer overflow vulnerability (CVE-2018-25221) located in the `chat.ghp` endpoint. This flaw allows an unauthenticated remote attacker to execute arbitrary code within the context of the application. The attack is achieved by sending a specially crafted HTTP GET request to the vulnerable endpoint, including an oversized `username` parameter. The excessive length of the username causes a buffer overflow, enabling the attacker to inject and execute…
