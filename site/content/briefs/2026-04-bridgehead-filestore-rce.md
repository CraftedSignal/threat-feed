---
title: BridgeHead FileStore Unauthenticated Remote Code Execution via Apache Axis2
slug: 2026-04-bridgehead-filestore-rce
description: BridgeHead FileStore versions prior to 24A are vulnerable to unauthenticated remote code execution via exposed Apache Axis2 administration module with default credentials, enabling attackers to upload malicious web services and execute arbitrary OS commands.
date: "2026-04-24T16:16:36Z"
type: coverage
types:
  - coverage
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

BridgeHead FileStore versions prior to 24A, released in early 2024, expose a critical security vulnerability. Specifically, the Apache Axis2 administration module is accessible on network endpoints with default credentials. This flaw allows unauthenticated remote attackers to execute arbitrary operating system commands. The vulnerability stems from insecure default configurations within the FileStore application and the underlying Axis2 web service framework. Successful exploitation grants complete control over the affected system, potentially leading to data breaches, system compromise, and further lateral movement within the network. This vulnerability poses a significant risk to organizations using vulnerable versions of BridgeHead FileStore.

## Attack Chain

1.  The attacker identifies a BridgeHead FileStore instance running a vulnerable version of the software on a network-accessible endpoint.
2.  The attacker accesses the Apache Axis2 administration console, which is exposed due to a misconfiguration.
3.  The attacker authenticates to the Axis2 admin console using default credentials, bypassing authentication controls.
4.  The attacker uploads a malicious Java archive (WAR file) containing a web service designed to execute arbitrary commands.
5.  The attacker deploys the malicious web service through the Axis2 administration interface.
6.  The attacker crafts a SOAP request to the deployed malicious web service, embedding the operating system command to be executed.
7.  The vulnerable FileStore instance processes the SOAP request, executing the attacker-controlled command on the host operating system.
8.  The attacker gains remote code execution, achieving complete control over the compromised system.

## Impact

Successful exploitation of CVE-2026-39920 allows unauthenticated attackers to execute arbitrary OS commands on systems running vulnerable versions of BridgeHead FileStore. This can lead to complete system compromise, data breaches, denial of service, and further lateral movement within the network. While the exact number of affected organizations is unknown, the widespread use of BridgeHead FileStore in data protection and archiving scenarios makes this a critical vulnerability. The consequences of a successful attack could include the loss of sensitive data, disruption of business operations, and significant financial losses.

## Recommendation

*   Apply the update to FileStore version 24A or later to remediate the vulnerability as mentioned in the product updates page ([https://www.bridgeheadsoftware.com/rapid-data-protection-product-updates/](https://www.bridgeheadsoftware.com/rapid-data-protection-product-updates/)).
*   Monitor web server logs for suspicious POST requests to the Axis2 administration console (`/axis2/servlet/AdminServlet`) as it is a key component of the exploitation. Use the "Detect Axis2 Admin Access" Sigma rule to identify unauthorized access attempts.
*   Implement network segmentation to limit the exposure of BridgeHead FileStore instances and the Axis2 administration module.
*   Review and enforce strong authentication policies for all web-based administration interfaces.
