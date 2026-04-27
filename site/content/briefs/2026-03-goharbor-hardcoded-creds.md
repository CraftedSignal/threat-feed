---
title: GoHarbor Harbor Hardcoded Credentials Vulnerability
slug: 2026-03-goharbor-hardcoded-creds
description: GoHarbor Harbor versions 2.15.0 and below contain a critical vulnerability (CVE-2026-4404) due to hardcoded credentials, allowing unauthenticated attackers to access the web UI, modify container images, and potentially compromise supply chains.
date: "2026-03-25T16:05:38Z"
severities:
  - critical
tags:
  - goharbor
  - hardcoded-credentials
  - vulnerability
  - supply-chain
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/ghsa-hj7x-hmf2-hc2p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4404
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-goharbor-harbor-patch-immediately
  - https://www.kb.cert.org/vuls/id/577436
rules:
  - title: Detect GoHarbor Harbor Web UI Login with Default Credentials (Simulated)
    description: Detects simulated authentication attempts to the GoHarbor Harbor web UI using known default credentials.  This rule requires enabling authentication logging within the Harbor webserver logs, as successful logins are not directly logged.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GoHarbor Harbor API Access from Unknown Source IP
    description: This rule detects API access to GoHarbor Harbor from a source IP address not in a defined allow list.  This helps highlight potentially unauthorized access following a successful exploit.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

GoHarbor Harbor, a widely-used open-source container registry, is vulnerable to CVE-2026-4404. This vulnerability affects versions 2.15.0 and below and stems from the presence of hardcoded credentials within the application's code. An attacker can leverage these default credentials to gain unauthorized access to the Harbor web UI. This allows them to view, modify, or delete container images, manage repositories, and perform administrative actions. Successful exploitation can lead to a supply…
