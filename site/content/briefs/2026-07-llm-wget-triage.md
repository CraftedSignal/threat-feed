---
title: LLM-Based Triage of Wget Activity on Linux Hosts
slug: 2026-07-llm-wget-triage
description: Elastic has developed a detection rule that monitors non-allowlisted `wget` activity on Linux hosts using Auditd Manager or Auditbeat, leveraging an Elastic LLM to triage `wget` executions for potential ingress tool transfer, command and control, or data exfiltration attempts to untrusted destinations, generating alerts only for high-confidence positive or suspicious verdicts.
date: "2026-07-20T20:24:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - endpoint
  - llm
  - linux
  - threat-detection
  - collection
  - command-and-control
  - exfiltration
  - auditd
  - detection-rule
vendors:
  - Elastic
products:
  - Elastic Stack
  - Auditd Manager
  - Auditbeat
  - General Purpose LLM v2
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The LLM triages activity to identify 'downloading a remote payload or script for later execution, command-and-control, ingress tool transfer'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The LLM triages activity to identify 'data exfiltration through --post-file, --post-data, or --body-file to an untrusted host'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The LLM considers if 'wget downloaded a payload or script, wrote content to an executable or temporary path, or used --post-file, --post-data, or --body-file to upload local data.'
    confidence_band: med
references:
  - https://www.elastic.co/docs/reference/query-languages/esql/esql-commands#esql-completion
  - https://www.elastic.co/security-labs/beyond-behaviors-ai-augmented-detection-engineering-with-esql-completion
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_wget_activity_auditd_llm_triage.toml
iocs:
  - type: ip
    value: 0.0.0.0
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 168.63.129.16
  - type: domain
    value: mcr.microsoft.com
  - type: domain
    value: acs-mirror.azureedge.net
  - type: domain
    value: packages.aks.azure.com
  - type: domain
    value: packages.microsoft.com
  - type: domain
    value: login.microsoftonline.com
  - type: domain
    value: management.azure.com
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: api.github.com
  - type: domain
    value: artifacts.elastic.co
  - type: domain
    value: download.elastic.co
ioc_counts:
  domain: 10
  ip: 3
rules:
  - title: Detect Suspicious Wget Activity to Remote Hosts
    description: Detects `wget` commands used to download content from or upload data to remote hosts, excluding common benign destinations. This rule targets the initial activity that would then be triaged by an LLM in an Elastic environment.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - exfiltration
    techniques:
      - T1048
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Elastic has released an LLM-powered detection rule designed to identify potentially malicious `wget` activity on Linux systems. This rule, updated in July 2026, integrates with Auditd Manager or Auditbeat to collect process execution events, specifically targeting `wget` invocations. It normalizes command-line arguments, redacts sensitive information like credentials, and then uses Elastic's General Purpose LLM v2 to assess whether the activity indicates ingress tool transfer (T1105), command and control (TA0011), or data exfiltration (T1048, T1005). The rule is configured to filter out known benign `wget` destinations, such as local loopbacks, cloud platform services (Azure, GCP), and common vendor repositories (Microsoft, GitHub, Elastic), to reduce false positives. Alerts are generated only for high-confidence (above 0.7) positive or suspicious verdicts from the LLM, providing security teams with intelligent triage for `wget` usage.

## Attack Chain

This brief describes a detection mechanism rather than an observed attack campaign. Therefore, a specific attack chain is not provided, as the rule monitors for general malicious `wget` activity, which can occur at various stages of an attack.

## Impact

Successful malicious `wget` activity on a Linux host can lead to severe consequences, including remote code execution if an attacker downloads and executes a malicious payload, establishment of persistent command and control (C2) channels for ongoing access, or unauthorized data exfiltration using `wget`'s upload functionalities (`--post-file`, `--post-data`, `--body-file`). The exposure of credentials or tokens via command-line arguments, even if redacted in logs, could facilitate further compromise or lateral movement. The detection rule aims to mitigate these impacts by identifying and triaging such activities promptly, preventing adversaries from achieving their objectives undetected.

## Recommendation

* Configure Auditd Manager or Auditbeat on all Linux endpoints to collect process execution events, including `process.name`, `process.args`, and `process.title`, as required by the detection rule.
* Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious `wget` activity, which can then be further triaged.
* Review the `iocs` list of explicitly excluded benign destinations and add any additional routine, verified benign `wget` destinations specific to your environment to your allow-lists to reduce false positives.
* Investigate high-confidence alerts generated by the rule by examining `Esql.verdict`, `Esql.confidence`, `Esql.summary`, `Esql.dest_host`, and `Esql.command_line_values` within your Elastic Stack.
* If payload execution, command-and-control, or data exfiltration is confirmed, isolate the affected host immediately.
* Rotate any credentials or tokens that may have been exposed in `wget` command lines, even if redacted in logs.
