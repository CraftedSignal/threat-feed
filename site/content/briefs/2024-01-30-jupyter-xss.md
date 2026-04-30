---
title: Jupyter Notebook Authentication Token Theft via CommandLinker XSS
slug: 2024-01-30-jupyter-xss
description: A stored Cross-Site Scripting (XSS) vulnerability in Jupyter Notebook versions 7.0.0 through 7.5.5 and JupyterLab versions up to 4.5.6 allows attackers to steal authentication tokens by tricking users into interacting with malicious notebook files, leading to complete account takeover via the Jupyter REST API.
date: "2026-04-30T17:25:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - jupyter
  - authentication
  - account-takeover
  - vulnerability
vendors:
  - Jupyter
  - NVIDIA
products:
  - '@jupyter-notebook/help-extension'
  - notebook
  - jupyterlab
  - '@jupyterlab/help-extension'
  - Jupyter Notebook
references:
  - https://github.com/advisories/GHSA-rch3-82jr-f9w9
  - https://jupyterlab.readthedocs.io/en/latest/user/commands.html#commands-in-markdown-output-and-files
rules:
  - title: Detect Jupyter Notebook CommandLinker XSS Attempt
    description: Detects potential XSS attacks in Jupyter Notebook by identifying suspicious requests to the command linker functionality.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Jupyter Notebook Token Theft via REST API Access
    description: Detects suspicious access to the Jupyter REST API after a potential token theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored Cross-Site Scripting (XSS) vulnerability has been identified in Jupyter Notebook and JupyterLab, impacting versions 7.0.0 through 7.5.5 of Jupyter Notebook and versions up to 4.5.6 of JupyterLab. Discovered by Daniel Teixeira of the NVIDIA AI Red Team, this flaw allows an attacker to craft malicious notebook files containing XSS payloads embedded within the command linker functionality. When a user opens and interacts with these files, the injected script executes, potentially stealing the user's authentication token. Successful exploitation grants the attacker full control over the user's Jupyter account, enabling them to read, modify, and create files, execute arbitrary code via running kernels, and establish shell access through created terminals. This vulnerability poses a significant risk to data confidentiality, integrity, and system availability.

## Attack Chain

1. Attacker crafts a malicious Jupyter Notebook file containing a stored XSS payload within the command linker functionality.
2. The attacker distributes the malicious notebook file to a target user (e.g., via email, shared repository, or compromised website).
3. The victim opens the malicious notebook file in a vulnerable version of Jupyter Notebook or JupyterLab.
4. The victim interacts with a seemingly legitimate control element within the notebook that is, in fact, part of the XSS payload.
5. The injected XSS code executes in the victim's browser, stealing their authentication token.
6. The attacker uses the stolen authentication token to authenticate to the Jupyter REST API.
7. The attacker gains complete control over the victim's Jupyter account.
8. The attacker performs malicious actions, such as reading files, modifying files, executing arbitrary code, or creating terminals for shell access.

## Impact

Successful exploitation of this XSS vulnerability enables complete account takeover, allowing attackers to read, modify, and create files, access running kernels and execute arbitrary code, and create terminals for shell access within the victim's Jupyter environment. This can lead to data exfiltration, code injection, and potential compromise of sensitive information stored within the Jupyter Notebook environment. Given the widespread use of Jupyter Notebook in data science, machine learning, and research environments, this vulnerability can have far-reaching consequences for individuals and organizations relying on these tools.

## Recommendation

*   Immediately upgrade Jupyter Notebook to version 7.5.6 or later, and JupyterLab to version 4.5.7 or later to patch CVE-2026-40171.
*   Apply the workaround to disable the help extension via CLI as specified in the advisory to mitigate the vulnerability until patching is possible.
*   Implement the hardening measure by disabling the command linker functionality via `overrides.json` to prevent XSS attacks, referencing the configuration details in the advisory.
*   Deploy the Sigma rule "Detect Jupyter Notebook CommandLinker XSS Attempt" to detect potential exploitation attempts based on specific HTTP request characteristics.
*   Educate users about the risks of opening untrusted Jupyter Notebook files and interacting with potentially malicious content.
