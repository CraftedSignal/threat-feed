---
title: Budibase Unauthenticated Remote Code Execution via Webhook
slug: 2026-04-budibase-rce
description: Budibase versions before 3.33.4 are susceptible to unauthenticated remote code execution, where a threat actor can trigger a Bash step within an automation via the public webhook endpoint, leading to code execution as root within the container.
date: "2026-04-03T16:16:41Z"
severities:
  - critical
tags:
  - CVE-2026-35216
  - budibase
  - rce
  - webhook
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35216
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35216
  - https://github.com/Budibase/budibase/security/advisories/GHSA-fcm4-4pj2-m5hf
  - https://github.com/Budibase/budibase/commit/f0c731b409a96e401445a6a6030d2994ff4ac256
  - https://github.com/Budibase/budibase/pull/18238
  - https://github.com/Budibase/budibase/releases/tag/3.33.4
rules:
  - title: Detect Budibase Webhook Automation Bash Execution
    description: Detects the execution of bash commands within Budibase automations potentially triggered by webhooks exploiting CVE-2026-35216
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Budibase Webhook Access
    description: Detects access to budibase webhook endpoints
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Budibase, an open-source low-code platform, is vulnerable to remote code execution (RCE) in versions prior to 3.33.4. This vulnerability, identified as CVE-2026-35216, allows an unauthenticated attacker to execute arbitrary commands on the Budibase server. The attack involves leveraging the public webhook endpoint to trigger an automation containing a Bash step. Due to the lack of authentication, malicious actors can directly interact with the webhook to initiate the execution. The process runs…
