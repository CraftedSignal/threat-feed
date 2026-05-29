---
title: PraisonAI Arbitrary File Write Vulnerability
slug: 2026-05-praisonai-file-write
description: PraisonAI versions 4.6.37 and earlier are vulnerable to arbitrary file write due to missing path validation in the `write_file` function when `workspace=None`, allowing an attacker to write attacker-controlled content to arbitrary file paths on the victim's system via a malicious webpage.
date: "2026-05-29T22:33:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary file write
  - web crawling
  - data exfiltration
vendors:
  - PraisonAI
products:
  - PraisonAI <= 4.6.37
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-hvhp-v2gc-268q
  - CVE-2026-47397
rules:
  - title: Detect PraisonAI Arbitrary File Write via Web Crawl
    description: Detects CVE-2026-47397 exploitation — PraisonAI agents calling write_file with attacker-controlled file paths from web crawling tasks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Writes Outside Workspace
    description: Detects attempts to write files outside a predefined workspace directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI versions up to 4.6.37 are susceptible to an arbitrary file write vulnerability (CVE-2026-47397) within its Python API. This flaw stems from the `write_file` function's lack of path validation when the `workspace` parameter is set to `None`, a default configuration in production environments. An attacker can exploit this by hosting a webpage containing hidden metadata that specifies an arbitrary file path and content. When a victim's PraisonAI agent crawls and analyzes this webpage, it autonomously calls the `write_file` function, writing the attacker-controlled content to the specified path on the victim's system. This vulnerability allows attackers to bypass injection defenses and LLM safety measures, as the agent performs normal operations triggered by the malicious metadata.

## Attack Chain

1. The attacker crafts a malicious webpage containing hidden metadata within a `<span>` element, defining the `output_file` and `output_content` parameters.
2. A victim uses the PraisonAI Python API to initiate a web crawling task, targeting the attacker's malicious webpage using the `web_crawl` tool.
3. The PraisonAI agent crawls the attacker-controlled webpage using the `web_crawl` tool, extracting the hidden metadata.
4. The agent parses the extracted metadata and identifies the `output_file` parameter, which specifies the arbitrary file path.
5. The agent, as part of its normal operation, autonomously calls the `write_file` function to write the extracted content to a file.
6. Because `workspace` is `None`, path validation is skipped in `code/tools/write_file.py:77-83`.
7. The `write_file` function writes the content defined by the `output_content` parameter to the file path specified by `output_file` on the victim's system.
8. The attacker achieves arbitrary file write on the victim's system, potentially leading to code execution or data exfiltration.

## Impact

Successful exploitation allows an attacker to write arbitrary files to the victim's system. This can lead to various malicious outcomes, including overwriting critical system files, injecting malicious code, or exfiltrating sensitive information. The vulnerability affects any user of PraisonAI who processes attacker-controlled webpages using the `web_crawl` tool, potentially impacting a wide range of users and applications that rely on PraisonAI for automated web analysis.

## Recommendation

*   Upgrade PraisonAI to a version later than 4.6.37 to incorporate the fix for CVE-2026-47397.
*   Deploy the Sigma rule "Detect PraisonAI Arbitrary File Write via Web Crawl" to detect exploitation attempts by monitoring for calls to the `write_file` function with attacker-controlled paths.
*   Implement robust input validation and sanitization measures to prevent malicious metadata injection into web pages processed by PraisonAI agents.
