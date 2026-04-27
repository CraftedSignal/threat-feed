---
title: Critical Remote Code Execution Vulnerability in Talend JobServer and Talend Runtime
slug: 2026-04-talend-rce
description: CVE-2026-6264, a critical deserialization vulnerability in Talend JobServer and Runtime, allows unauthenticated remote code execution via the JMX monitoring port, leading to complete system compromise.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - rce
  - deserialization
  - talend
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6264
    cvss: 9.8
    epss: 0.00237
references:
  - https://ccb.belgium.be/advisories/warning-critical-remote-code-execution-talend-jobserver-and-talend-runtime-patch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6264
  - https://github.com/advisories/GHSA-2m83-cjg7-5x73
  - https://community.qlik.com/t5/Official-Support-Articles/Critical-Security-fix-for-the-Qlik-Talend-JobServer-and-Talend/tac-p/2541974
rules:
  - title: Detect JMX traffic on Talend JobServer/Runtime
    description: Detects network connections to the JMX monitoring port commonly used by Talend JobServer and Runtime, which may indicate exploitation of CVE-2026-6264.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Spawned by Java Related to JMX
    description: Detects potential exploitation of Talend JobServer/Runtime via JMX by monitoring for suspicious processes spawned by Java.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical remote code execution vulnerability, CVE-2026-6264, has been identified in Talend JobServer and Talend Runtime, core components of the Talend data integration platform. Versions affected include Talend JobServer 7.3 (before TPS-6018) and 8.0 (before TPS-6017), as well as Talend Runtime 7.3 (before 7.3.1-R2026-01) and 8.0 (before 8.0.1.R2026-01-RT). The vulnerability stems from insecure deserialization of untrusted data through the JMX monitoring port. Successful exploitation allows…
