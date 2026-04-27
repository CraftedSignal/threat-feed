---
title: BridgeHead FileStore Unauthenticated Remote Code Execution via Apache Axis2
slug: 2026-04-bridgehead-filestore-rce
description: BridgeHead FileStore versions prior to 24A are vulnerable to unauthenticated remote code execution via exposed Apache Axis2 administration module with default credentials, enabling attackers to upload malicious web services and execute arbitrary OS commands.
date: "2026-04-24T16:16:36Z"
severities:
  - critical
tags:
  - rce
  - cve-2026-39920
  - apache axis2
  - default credentials
  - web service
vendors:
  - BridgeHead Software
  - Apache
products:
  - FileStore
  - Axis2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-39920
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39920
  - https://axis.apache.org/axis2/java/core/docs/webadminguide.html
  - https://gist.github.com/VAMorales/9e6a13d7529c079a363930dff48be3ba
  - https://issues.apache.org/jira/browse/AXIS2-4279
  - https://www.bridgeheadsoftware.com/rapid-data-protection-product-updates/
  - https://www.vulncheck.com/advisories/bridgehead-filestore-24a-apache-axis2-default-credentials-rce
rules:
  - title: Detect Axis2 Admin Access
    description: Detects access to the Apache Axis2 administration console which is often targeted in exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WAR File Upload to Axis2 Admin
    description: Detects the upload of a WAR file to the Axis2 admin console, a common step in deploying malicious web services.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

BridgeHead FileStore versions prior to 24A, released in early 2024, expose a critical security vulnerability. Specifically, the Apache Axis2 administration module is accessible on network endpoints with default credentials. This flaw allows unauthenticated remote attackers to execute arbitrary operating system commands. The vulnerability stems from insecure default configurations within the FileStore application and the underlying Axis2 web service framework. Successful exploitation grants…
