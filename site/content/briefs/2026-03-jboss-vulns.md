---
title: Red Hat JBoss Enterprise Application Platform Multiple Vulnerabilities
slug: 2026-03-jboss-vulns
description: An anonymous remote attacker can exploit multiple vulnerabilities in Red Hat JBoss Enterprise Application Platform to cause a denial-of-service condition, manipulate data, and conduct further attacks such as cache poisoning and session hijacking.
date: "2026-03-25T10:23:05Z"
severities:
  - high
tags:
  - jboss
  - undertow
  - denial-of-service
  - cache-poisoning
  - session-hijacking
  - webserver
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Obtain Capabilities
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0054
rules:
  - title: Detect Suspicious HTTP Methods
    description: Detects suspicious HTTP methods that might indicate an attack attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple 404 Errors from Same Source
    description: Detects multiple 404 errors from the same source IP, which could indicate scanning for vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within the Red Hat JBoss Enterprise Application Platform. An unauthenticated, remote attacker can exploit these flaws to trigger a denial-of-service (DoS) condition, manipulate sensitive data, and facilitate subsequent attacks, including cache poisoning and session hijacking. The vulnerabilities exist in the Undertow component. While specific CVEs are not listed in the advisory, the impact could be significant, leading to service disruption and potential data…
