---
title: Easy Chat Server 3.1 Denial of Service Vulnerability (CVE-2019-25613)
slug: 2026-03-easy-chat-dos
description: Easy Chat Server 3.1 is vulnerable to a denial-of-service attack where a remote attacker can crash the application by sending oversized data in the message parameter via a POST request to the body2.ghp endpoint after establishing a session, leading to service unavailability.
date: "2026-03-24T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - dos
  - cve-2019-25613
  - easy-chat-server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25613
  - https://www.exploit-db.com/exploits/46806
  - https://www.vulncheck.com/advisories/easy-chat-server-denial-of-service-via-message-parameter
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect POST Requests to body2.ghp with Large Message Parameter
    description: Detects POST requests to body2.ghp with a message parameter exceeding a defined threshold, indicating a potential denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
  - title: Detect Access to chat.ghp Followed by body2.ghp with Large Message
    description: Detects access to chat.ghp followed by a POST request to body2.ghp with an unusually large message, indicating a potential denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
rules_count: 2
---

Easy Chat Server 3.1 is susceptible to a denial-of-service (DoS) vulnerability identified as CVE-2019-25613. This vulnerability allows an unauthenticated remote attacker to crash the application by sending an excessively large message parameter. The attack involves first establishing a session with the server via the `chat.ghp` endpoint. The attacker then sends a specially crafted POST request to the `body2.ghp` endpoint, including a message parameter containing oversized data. Successful…
