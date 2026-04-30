---
title: Critical RCE Vulnerabilities in Spinnaker
slug: 2026-04-spinnaker-rce
description: Critical vulnerabilities CVE-2026-32613 and CVE-2026-32604 in Spinnaker allow authenticated attackers to execute arbitrary code due to insufficient input validation in expression parsing and gitrepo artifact handling, potentially leading to complete system compromise.
date: "2026-04-22T14:46:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - spinnaker
vendors:
  - Spinnaker
products:
  - Spinnaker
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32613
    cvss: 9.9
    epss: 0.00057
  - id: CVE-2026-32604
    cvss: 9.9
    epss: 0.00082
references:
  - https://ccb.belgium.be/advisories/warning-critical-cve-2026-32613-cve-2026-32604-spinnaker-patch-immediately
  - https://github.com/spinnaker/spinnaker/security/advisories/GHSA-x3j7-7pgj-h87r
  - https://github.com/spinnaker/spinnaker/security/advisories/GHSA-69rw-45wj-g4v6
  - https://feedly.com/cve/CVE-2026-32613
  - https://feedly.com/cve/CVE-2026-32604
rules:
  - title: Detect Suspicious Spinnaker Pipeline Configuration Changes
    description: Detects changes to Spinnaker pipeline configurations that may indicate malicious activity, such as the injection of malicious expressions or gitrepo artifacts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Spinnaker Pipeline Executions with Suspicious Artifacts
    description: Detects Spinnaker pipeline executions that involve potentially malicious gitrepo artifacts, indicated by unusual branch names or file paths.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Two critical remote code execution (RCE) vulnerabilities, CVE-2026-32613 and CVE-2026-32604, have been discovered in Spinnaker, an open-source multi-cloud continuous delivery platform. These vulnerabilities stem from insufficient input validation and sanitization. CVE-2026-32613 relates to expression parsing, allowing for the execution of malicious expressions via untrusted input in pipeline expressions. CVE-2026-32604 arises from improper handling of gitrepo artifact types, specifically regarding the sanitization of user-controlled input like branch names and file paths. An attacker with pipeline configuration access can exploit these flaws to achieve arbitrary code execution on the affected system. The Centre for Cybersecurity Belgium (CCB) strongly advises immediate patching and enhanced monitoring.

## Attack Chain

1.  Attacker gains access to Spinnaker pipeline configuration, either through compromised credentials or exploiting a separate authentication vulnerability.
2.  For CVE-2026-32613, the attacker injects a malicious expression into a pipeline configuration, leveraging the insufficient input validation in expression parsing.
3.  For CVE-2026-32604, the attacker crafts a malicious gitrepo artifact definition within a Spinnaker pipeline, specifying a branch name or file path containing injected code.
4.  The Spinnaker pipeline is triggered, either manually or automatically based on configured triggers.
5.  During pipeline execution, the malicious expression (CVE-2026-32613) or gitrepo artifact (CVE-2026-32604) is processed.
6.  The injected code is executed within the context of the Spinnaker service, gaining the privileges of the Spinnaker process.
7.  The attacker leverages the code execution to establish persistence, move laterally within the network, or exfiltrate sensitive data.
8.  The final objective is achieved, such as complete system compromise, data breach, or disruption of services.

## Impact

Successful exploitation of CVE-2026-32613 or CVE-2026-32604 allows an attacker to execute arbitrary code on the Spinnaker server, potentially leading to complete system compromise. This could result in the theft of sensitive credentials, modification of deployment pipelines, deployment of malicious code to production environments, and disruption of critical services. Given Spinnaker's role in continuous delivery, a successful attack can have a wide-ranging impact on the organization's software development lifecycle.

## Recommendation

*   Immediately patch Spinnaker to the latest version to remediate CVE-2026-32613 and CVE-2026-32604 as recommended by the CCB.
*   Upscale monitoring and detection capabilities to identify any suspicious activity related to these vulnerabilities, as suggested by the CCB.
*   Implement strict input validation and sanitization measures for all user-controlled input within Spinnaker pipeline configurations to prevent future exploitation of similar vulnerabilities.
