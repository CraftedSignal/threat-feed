---
title: BentoML SSTI via Unsandboxed Jinja2 in Dockerfile Generation
slug: 2024-02-bentoml-ssti
description: BentoML versions 1.4.37 and earlier are vulnerable to server-side template injection (SSTI), where the Dockerfile generation function uses an unsandboxed jinja2.Environment allowing arbitrary Python code execution on the host machine when a malicious bento archive is imported and containerized, bypassing container isolation and potentially granting full access to the host filesystem and environment variables.
date: "2026-04-03T23:14:15Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - ssti
  - bentoml
  - code-execution
  - docker
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-v959-cwq9-7hr6
rules:
  - title: Detect BentoML SSTI Payload in Dockerfile Template
    description: Detects potential Server-Side Template Injection (SSTI) payloads in Dockerfile templates, specifically targeting BentoML's use of Jinja2.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Process Execution from BentoML
    description: Detects suspicious process execution originating from the BentoML process, which may indicate exploitation of the SSTI vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

BentoML versions 1.4.37 and earlier contain a critical vulnerability related to server-side template injection (SSTI). The vulnerability stems from the use of an unsandboxed Jinja2 environment within the `generate_containerfile()` function, which is responsible for creating Dockerfiles. By crafting a malicious bento archive containing a specially crafted `dockerfile_template`, an attacker can inject arbitrary Python code that executes directly on the host machine when a victim imports and containerizes the bento using `bentoml containerize`. This vulnerability bypasses all container isolation mechanisms and gives the attacker full access to the host's filesystem, environment variables, and potentially other sensitive information. The lack of input validation during the import process allows the malicious template to be embedded within the bento archive undetected until the containerization process.

## Attack Chain

1.  Attacker crafts a malicious `bentofile.yaml` file containing a `dockerfile_template` directive pointing to a Jinja2 template with an SSTI payload.
2.  The attacker builds a bento using `bentoml build`, which copies the malicious template into the bento archive at `env/docker/Dockerfile.template`.
3.  The attacker exports the bento as a `.bento` or `.tar.gz` archive and distributes it to victims.
4.  A victim imports the malicious bento archive using `bentoml import bento.tar`. No validation of the template content is performed during the import.
5.  The victim attempts to containerize the imported bento using `bentoml containerize`, triggering the `construct_containerfile()` function.
6.  The `construct_containerfile()` function detects the presence of the `Dockerfile.template` and sets the `dockerfile_template` attribute in the Docker options.
7.  The `generate_containerfile()` function loads the attacker-controlled template into an unsandboxed Jinja2 environment.
8.  The template is rendered, resulting in arbitrary Python code execution on the victim's host machine, outside of any containerized environment. This allows the attacker to achieve full host compromise.

## Impact

Successful exploitation allows arbitrary code execution on the host machine of any user who imports and containerizes the malicious bento archive. This provides the attacker with: full access to the host filesystem, the ability to install backdoors or pivot to other systems, and access to sensitive information such as credentials and API keys stored in environment variables. Due to the placement of the malicious code within a bento archive, and the nature of the containerize operation, users may be unaware of the risk and impact of this vulnerability.

## Recommendation

*   Apply the patched version of BentoML (later than 1.4.37) to remediate CVE-2026-35044.
*   Deploy the Sigma rule "Detect BentoML SSTI Payload in Dockerfile Template" to identify potentially malicious Jinja2 templates being written to disk.
*   Monitor process creation events for the execution of suspicious commands originating from the `bentoml` process, particularly after importing a bento archive, to catch potential exploitation attempts using the rule "Detect Suspicious Process Execution from BentoML".
*   Implement strict input validation and sanitization for any user-provided templates or configuration files to prevent server-side template injection vulnerabilities, as described in the overview.
*   Review and restrict the extensions used within the Jinja2 environment to only those absolutely necessary for Dockerfile generation, following the recommended fix in the source.
