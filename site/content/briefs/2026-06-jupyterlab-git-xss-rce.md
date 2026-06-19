---
title: JupyterLab Git Extension Stored XSS to RCE (CVE-2026-54527)
slug: 2026-06-jupyterlab-git-xss-rce
description: A stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-54527, in the `jupyterlab-git` JupyterLab extension (versions >= 0.30.0b3, < 0.54.0a1), specifically in `PlainTextDiff.ts`, allows an adversary with Git commit access to execute arbitrary JavaScript in a victim's browser and achieve Remote Code Execution (RCE) on the JupyterLab server by crafting a malicious filename in a Git commit that, when viewed as a rename diff, triggers the XSS payload to steal `_xsrf` cookies, open a terminal, and execute arbitrary shell commands to exfiltrate data.
date: "2026-06-19T20:01:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - rce
  - jupyterlab
  - git
  - web-vulnerability
  - software-supply-chain
  - ghsa
vendors:
  - Jupyter Project
products:
  - jupyterlab-git (pip >= 0.30.0b3, < 0.54.0a1)
  - jupyterlab-git-core (pip >= 0.30.0b3, < 0.54.0a1)
  - '@jupyterlab/git (npm >= 0.30.0b3, < 0.54.0-a1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-f962-v9hr-pfg5
rules:
  - title: Detects CVE-2026-54527 Exploitation — JupyterLab Terminal Creation
    description: Detects POST requests to JupyterLab's /api/terminals endpoint, indicating a potential attempt to open a remote shell via the XSS vulnerability (CVE-2026-54527). This can occur after successful client-side XSS exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
  - title: Detects CVE-2026-54527 Exploitation — Suspicious JupyterLab Child Process
    description: Detects the creation of suspicious child processes (e.g., shell interpreters, data exfiltration tools) spawned by JupyterLab processes, which can indicate successful Remote Code Execution (RCE) via CVE-2026-54527. This rule targets the post-exploitation phase where arbitrary shell commands are executed.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1036.003
      - T1059
      - T1071.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Amazon Web Services (AWS) Security discovered CVE-2026-54527, a high-severity stored cross-site scripting (XSS) vulnerability within the `jupyterlab-git` JupyterLab extension (versions >= 0.30.0b3, < 0.54.0a1). This flaw specifically resides in the `createHeader()` method of the `PlainTextDiff.ts` component, which insecurely renders Git filenames directly to `innerHTML` without sanitization when displaying diffs for renamed files in commit history. Exploitation requires an adversary to have commit access to a shared Git repository; they craft a malicious filename (e.g., `<img src=x onerror=eval(atob("base64_payload"))>.py`), rename it in a subsequent commit, and push it. When a victim views the rename diff of this file in the Git History tab, the injected JavaScript executes in their browser, reading the `_xsrf` cookie, opening a JupyterLab terminal via `POST /api/terminals`, and subsequently executing arbitrary shell commands to achieve full Remote Code Execution (RCE). This allows attackers to exfiltrate secrets, credentials, and sensitive data from the victim's JupyterLab environment. The vulnerability impacts organizations utilizing JupyterLab with the vulnerable `jupyterlab-git` extension installed, potentially leading to widespread compromise of development and data science environments.

## Attack Chain

1.  An adversary with commit access to a shared Git repository crafts a file with a malicious filename containing a JavaScript payload (e.g., `<img src=x onerror=eval(atob("base64_payload"))>.py`).
2.  The adversary performs a Git commit, renaming the crafted file, and pushes both the file creation and rename commits to the shared Git repository.
3.  A victim user clones or pulls the repository into their JupyterLab environment.
4.  The victim navigates to the Git History tab within JupyterLab, clicks the commit containing the rename, and then clicks the renamed malicious file to view its diff.
5.  JupyterLab's `PlainTextDiff.ts` component, specifically the `createHeader()` method, renders the unsanitized malicious filename directly into the Document Object Model (DOM) via `innerHTML`, executing the embedded JavaScript payload in the victim's browser session.
6.  The executed JavaScript reads the victim's `_xsrf` cookie, constructs and sends a `POST` request to the JupyterLab server's `/api/terminals` endpoint to open a new terminal session.
7.  The JavaScript establishes a WebSocket connection to the newly created terminal and sends arbitrary shell commands for execution on the underlying JupyterLab server.
8.  The shell commands execute with the privileges of the JupyterLab server process, leading to Remote Code Execution (RCE) and potential exfiltration of credentials or sensitive data from the victim's environment.

## Impact

Successful exploitation of CVE-2026-54527 leads to full Remote Code Execution (RCE) on the JupyterLab server where the victim's session is running. This grants an attacker unauthorized access to the victim's code, data, environment variables, and any credentials accessible from that environment. Attackers can leverage this RCE to exfiltrate sensitive information, install backdoors, move laterally within the network, or disrupt development and data science workflows. The attack vectors are widespread across any organization using JupyterLab with the vulnerable `jupyterlab-git` extension in a collaborative Git environment.

## Recommendation

1.  Immediately patch the `jupyterlab-git` extension to a version equal to or greater than 0.54.0a1 to remediate CVE-2026-54527.
2.  Deploy the Sigma rules "Detects CVE-2026-54527 Exploitation — JupyterLab Terminal Creation" and "Detects CVE-2026-54527 Exploitation — Suspicious JupyterLab Child Process" to your SIEM and tune them for your environment's baseline JupyterLab activity.
3.  Enable comprehensive `webserver` logging for all JupyterLab instances to capture `POST` requests to `/api/terminals` and other suspicious API endpoints, enabling the "Detects CVE-2026-54527 Exploitation — JupyterLab Terminal Creation" rule.
4.  Enable `process_creation` logging on all servers hosting JupyterLab instances to monitor for unusual child processes spawned by JupyterLab or Python processes, enabling the "Detects CVE-2026-54527 Exploitation — Suspicious JupyterLab Child Process" rule.
