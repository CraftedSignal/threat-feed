---
title: Parse Server LiveQuery Protected Field Leak via Shared Mutable State
slug: 2024-01-02-parse-server-livequery-leak
description: Parse Server versions before 8.6.65 and between 9.0.0 and 9.7.0-alpha.9 are vulnerable to a data leak where protected fields and authentication data can be exposed to unauthorized clients due to shared mutable objects across concurrent LiveQuery subscribers.
date: "2026-03-30T17:40:59Z"
severities:
  - high
tags:
  - parse-server
  - livequery
  - data-leak
  - cve-2026-34363
references:
  - https://github.com/advisories/GHSA-m983-v2ff-wq65
  - https://github.com/parse-community/parse-server/pull/10330
  - https://github.com/parse-community/parse-server/pull/10331
rules:
  - title: Potential LiveQuery Data Leak Attempt
    description: Detects multiple LiveQuery subscriptions to the same class from different IP addresses within a short timeframe, which could indicate an attempt to exploit the shared mutable state vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detecting AfterEvent Trigger Abuse via LiveQuery
    description: This rule detects modifications to a class immediately after a LiveQuery event, which could indicate an attacker is exploiting the AfterEvent trigger vulnerability to leak data.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Parse Server Version in User-Agent
    description: Detects Parse Server version disclosed in User-Agent header
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Parse Server, an open-source backend for web and mobile applications, is susceptible to a vulnerability in its LiveQuery functionality. This issue stems from the concurrent handling of multiple subscribers using shared mutable objects. Specifically, when several clients subscribe to the same class via LiveQuery, event handlers process each subscriber concurrently, leading to a situation where sensitive data filters modify shared objects in-place. This can cause protected fields and…
