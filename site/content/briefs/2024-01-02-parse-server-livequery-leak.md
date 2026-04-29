---
title: Parse Server LiveQuery Protected Field Leak via Shared Mutable State
slug: 2024-01-02-parse-server-livequery-leak
description: Parse Server versions before 8.6.65 and between 9.0.0 and 9.7.0-alpha.9 are vulnerable to a data leak where protected fields and authentication data can be exposed to unauthorized clients due to shared mutable objects across concurrent LiveQuery subscribers.
date: "2026-03-30T17:40:59Z"
type: coverage
types:
  - coverage
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

Parse Server, an open-source backend for web and mobile applications, is susceptible to a vulnerability in its LiveQuery functionality. This issue stems from the concurrent handling of multiple subscribers using shared mutable objects. Specifically, when several clients subscribe to the same class via LiveQuery, event handlers process each subscriber concurrently, leading to a situation where sensitive data filters modify shared objects in-place. This can cause protected fields and authentication data to be leaked to clients that should not have access to them, or lead to incomplete objects being received by clients that should see the data. The vulnerability affects Parse Server deployments using LiveQuery with protected fields or afterEvent triggers when multiple clients are subscribed to the same class. Specifically, versions before 8.6.65 and versions 9.0.0 up to (but not including) 9.7.0-alpha.9 are vulnerable. Patches have been released to address this vulnerability by deep-cloning the shared objects, ensuring isolation between subscribers.

## Attack Chain

1.  Attacker identifies a Parse Server deployment using LiveQuery with protected fields or afterEvent triggers.
2.  Attacker determines the server is running a vulnerable version of Parse Server (e.g., 9.6.0).
3.  Attacker subscribes to a LiveQuery for a specific class containing protected fields.
4.  A legitimate user subscribes to the same LiveQuery for the same class.
5.  The server processes the legitimate user's subscription first. A sensitive data filter removes a protected field from the shared object.
6.  The server then processes the attacker's subscription. Because the object has already been filtered by the previous subscriber's request, the attacker receives the object without the protected field check being applied.
7.  Attacker gains unauthorized access to data they should not be able to view.
8.  The attacker can potentially exploit this information to further compromise the application or access other sensitive data.

## Impact

This vulnerability could lead to the exposure of sensitive information, including protected fields and authentication data, to unauthorized users. The number of affected deployments is unknown, but any Parse Server instance utilizing LiveQuery with protected fields or afterEvent triggers is potentially at risk. Successful exploitation could result in data breaches, privacy violations, and unauthorized access to sensitive application resources. The severity is high due to the potential for widespread data leakage and the lack of a workaround prior to patching.

## Recommendation

*   Upgrade Parse Server to version 8.6.65 or later, or version 9.7.0-alpha.9 or later to patch CVE-2026-34363.
*   Monitor Parse Server logs for unusual LiveQuery subscription patterns that might indicate an attempted exploitation. While there are no specific rules provided here, correlate server logs with application usage to detect anomalies.
*   If unable to immediately patch, consider disabling LiveQuery functionality or removing protected fields as a temporary mitigation, though this will impact application functionality.
