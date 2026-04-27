---
title: Critical RCE Vulnerabilities in Spinnaker
slug: 2026-04-spinnaker-rce
description: Critical vulnerabilities CVE-2026-32613 and CVE-2026-32604 in Spinnaker allow authenticated attackers to execute arbitrary code due to insufficient input validation in expression parsing and gitrepo artifact handling, potentially leading to complete system compromise.
date: "2026-04-22T14:46:46Z"
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

Two critical remote code execution (RCE) vulnerabilities, CVE-2026-32613 and CVE-2026-32604, have been discovered in Spinnaker, an open-source multi-cloud continuous delivery platform. These vulnerabilities stem from insufficient input validation and sanitization. CVE-2026-32613 relates to expression parsing, allowing for the execution of malicious expressions via untrusted input in pipeline expressions. CVE-2026-32604 arises from improper handling of gitrepo artifact types, specifically…
