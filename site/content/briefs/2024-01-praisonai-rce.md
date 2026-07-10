---
title: PraisonAI Remote Code Execution via YAML Deserialization
slug: 2024-01-praisonai-rce
description: PraisonAI is vulnerable to remote code execution (RCE) due to insecure YAML deserialization, allowing attackers to execute arbitrary code by uploading malicious agent definition files, affecting versions 4.5.114 and earlier.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - yaml deserialization
  - praisonai
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-32vr-5gcf-3pw2
rules:
  - title: Detect Suspicious YAML Deserialization
    description: Detects process creation initiated as a result of js-yaml deserializing a malicious YAML file.  This may indicate an attempt to exploit a YAML deserialization vulnerability such as CVE-2026-39890.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Malicious Agent Upload
    description: Detects creation of files in /tmp directory after praisonai executes node.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI versions 4.5.114 and earlier are susceptible to remote code execution (RCE) due to unsafe handling of YAML deserialization. The vulnerability resides in the `AgentService.loadAgentFromFile` method, which uses the `js-yaml` library to parse YAML files without enforcing a safe schema. This allows an attacker to inject malicious YAML payloads containing JavaScript code (e.g., using the `!!js/function` tag) that is executed when the agent definition file is loaded. The attack vector involves uploading a crafted YAML file as an agent definition through a vulnerable API endpoint. Successful exploitation leads to arbitrary code execution on the server, potentially compromising the entire system.

## Attack Chain

1.  Attacker identifies a PraisonAI instance running a vulnerable version (<= 4.5.114).
2.  Attacker crafts a malicious YAML file containing an embedded JavaScript payload using the `!!js/function` tag. The payload is designed to execute arbitrary commands on the server.
3.  Attacker leverages an API endpoint that uses `AgentService.loadAgentFromFile` to upload the malicious YAML file as an agent definition.
4.  The PraisonAI server parses the uploaded YAML file using the vulnerable `js-yaml.load` function, without a safe schema.
5.  The `!!js/function` tag triggers the execution of the embedded JavaScript code.
6.  The attacker's payload executes arbitrary commands on the server, such as creating a file in the /tmp directory (as demonstrated in the PoC).
7.  Attacker achieves remote code execution and can perform actions such as data theft, installing backdoors, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the PraisonAI server. This can lead to complete compromise of the server, including unauthorized access to sensitive data, installation of malware, and further network penetration. The vulnerability affects PraisonAI instances running version 4.5.114 and earlier, potentially impacting all users of the affected versions.

## Recommendation

*   Immediately upgrade PraisonAI to a patched version that addresses CVE-2026-39890.
*   Deploy the provided Sigma rule `Detect Suspicious YAML Deserialization` to identify attempts to exploit the vulnerability based on process creation events.
*   Modify the `AgentService.loadAgentFromFile` method to use `js-yaml` with a safe schema such as `JSON_SCHEMA` as described in the advisory.
*   Implement strict input validation and sanitization for all file uploads, especially agent definition files, to prevent the injection of malicious YAML payloads.
*   Implement access controls for API endpoints used to upload agent definitions to restrict access to trusted users only.
