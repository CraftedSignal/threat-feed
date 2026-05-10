---
title: JupyterLab Command Execution via Crafted HTML Content
slug: 2026-05-jupyterlab-command-execution
description: JupyterLab's HTML sanitizer allows execution of arbitrary commands via specially crafted HTML content in notebooks or Markdown files due to improper handling of `data-commandlinker-command` and `data-commandlinker-args` attributes.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - jupyterlab
  - command-execution
  - html-injection
products:
  - jupyterlab (<= 4.5.6)
  - notebook (>= 7.0.0, <= 7.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-mqcg-5x36-vfcg
rules:
  - title: Detect JupyterLab Command Execution via data-commandlinker-command
    description: Detects process execution originating from JupyterLab with command linker attributes, indicating potential command execution vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect JupyterLab data-commandlinker-command Attribute in Network Connections
    description: Detects network connections originating from JupyterLab processes where the command line includes 'data-commandlinker-command', which could indicate exploitation of the command execution vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability exists in JupyterLab and Notebook where specially crafted HTML content can be embedded within a notebook or Markdown file. This content leverages the `data-commandlinker-command` and `data-commandlinker-args` attributes, which are improperly sanitized. When a user opens the malicious notebook or Markdown file and clicks on a deceptively crafted button, it triggers the execution of arbitrary JupyterLab commands without further user interaction or code submission. This can lead to arbitrary code execution, file deletion, or denial of service. The vulnerability affects JupyterLab versions 4.5.6 and earlier, as well as Notebook versions 7.0.0 through 7.5.5. A patch is available in JupyterLab 4.5.7 to address this issue. This vulnerability poses a significant risk as it only requires a single click from the user to initiate malicious actions.

## Attack Chain

1. Attacker crafts a malicious notebook or Markdown file containing an HTML cell output.
2. The HTML cell includes a `<button>` element with `data-commandlinker-command` and `data-commandlinker-args` attributes set to a malicious command.
3. The attacker distributes the malicious file via email, GitHub, or a Binder link.
4. Victim opens the file in JupyterLab or Notebook.
5. The malicious HTML is rendered in the output area, displaying a deceptive button visually indistinguishable from legitimate widgets.
6. The victim clicks on the button.
7. `CommandLinker` captures the click event on `document.body`.
8. The `CommandLinker` executes the command specified in the `data-commandlinker-command` attribute, leading to arbitrary code execution, file deletion, or other malicious actions.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary code execution within the context of the JupyterLab server. This could allow an attacker to delete files, potentially causing unrecoverable data loss. In multi-tenant environments, this could lead to denial-of-service by exhausting server resources. In certain browser configurations (Chromium-based), attackers can potentially gain full terminal access via multi-click attacks combined with clipboard access. The affected products are JupyterLab versions up to 4.5.6 and Notebook versions 7.0.0 through 7.5.5.

## Recommendation

*   Upgrade to JupyterLab version 4.5.7 or later to patch CVE-2026-42557.
*   For downstream applications, disable the `CommandLinker` during initialization as described in the advisory.
*   Implement the hardening steps by setting `"allowCommandLinker": false` in the `overrides.json` file.
*   Educate users about the risks of opening notebooks and Markdown files from untrusted sources to prevent T1204.002 (User Execution).
