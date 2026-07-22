---
title: JupyterLab Cross-site Scripting via Crafted Settings File
slug: 2026-07-jupyterlab-xss
description: A cross-site scripting (XSS) vulnerability exists in JupyterLab versions 3.3.0 through 4.5.9 and 4.6.0 through 4.6.1, allowing arbitrary code execution because notebook display settings in the `overrides.json` file are not properly validated, enabling an attacker to craft a malicious file which, when imported by a user or automatically applied on a multi-tenant file system, can execute hidden instructions and compromise user data.
date: "2026-07-22T23:19:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - jupyterlab
  - code-execution
  - vulnerability
  - cloud
vendors:
  - Project Jupyter
products:
  - JupyterLab (3.3.0-4.5.9)
  - JupyterLab (4.6.0-4.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: A user can import a crafted `overrides.json` through the `Import` button in the Settings Editor, having received it from another party.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a crafted settings file could contain hidden instructions that run as code inside JupyterLab when imported, instead of only changing a display preference.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: If an attacker can write to a directory JupyterLab loads settings from (e.g. on shared or multi-tenant file system), they could place a crafted `overrides.json` that is applied to another user automatically at startup.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: a crafted settings file could contain hidden instructions
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This could allow an attacker to read or modify that user's notebooks and files
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: run code on the user's behalf through the notebook server, including on any connected kernel.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-pppj-hq3g-57pj
---

JupyterLab versions 3.3.0 through 4.5.9 and 4.6.0 through 4.6.1 are affected by a cross-site scripting (XSS) vulnerability related to improper validation of notebook display settings within the `overrides.json` file. This flaw, tracked as a GitHub Security Advisory (GHSA-pppj-hq3g-57pj) with a pending CVE, allows an attacker to embed malicious code within a crafted `overrides.json` file. When this file is either deliberately imported by a user via the Settings Editor's "Import" button or automatically applied due to write access on a multi-tenant file system, the embedded code executes within the victim's JupyterLab session. This enables an attacker to perform actions such as reading or modifying the user's notebooks and files, and running arbitrary code through the associated notebook server and kernels, thereby compromising the user's environment. The vulnerability stems from the expectation that settings files only modify display preferences, not execute code.

## Attack Chain

1. Attacker crafts a malicious `overrides.json` file containing XSS payloads designed to bypass JupyterLab's validation for certain notebook display settings.
2. **Initial Access Option 1 (User Interaction):** Attacker delivers the malicious `overrides.json` to a victim, potentially via social engineering, and convinces them to import it through the JupyterLab Settings Editor's "Import" button.
3. **Initial Access Option 2 (Privileged Write Access):** Attacker with write access to a shared or multi-tenant file system places the malicious `overrides.json` in a directory from which JupyterLab automatically loads user settings.
4. JupyterLab loads and processes the malicious `overrides.json` file, either manually imported or automatically applied at startup.
5. Due to insufficient validation of the embedded settings, the XSS payload executes within the victim's JupyterLab session, running with the user's privileges.
6. The attacker's code gains the ability to read or modify the victim's notebooks and other associated files.
7. The attacker's code can execute arbitrary commands on the victim's behalf through the Jupyter notebook server, potentially interacting with connected computational kernels.
8. The ultimate objective is to compromise user data, intellectual property, or gain further access to the underlying infrastructure through the hijacked session.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code within the victim's JupyterLab session with the same privileges as the affected user. This directly translates to the ability to read, modify, and exfiltrate the user's notebooks and other files accessible through JupyterLab. Furthermore, the attacker can leverage the compromised session to run code on the user's behalf through the associated Jupyter notebook server, potentially interacting with any connected computational kernels. While no specific victim counts or targeted sectors are identified in the advisory, any organization utilizing JupyterLab, especially in shared or multi-tenant environments, is at risk of intellectual property theft, data manipulation, or unauthorized resource utilization.

## Recommendation

* Upgrade JupyterLab to version 4.6.2 or 4.5.10 immediately to apply the security patches addressing the XSS vulnerability.
* Establish and enforce a trusted process for distributing JupyterLab configuration files, discouraging users from importing arbitrary `overrides.json` files from untrusted sources.
* For multi-tenant or shared file systems, restrict write permissions on JupyterLab application settings directories and other configuration paths to prevent unauthorized users from placing malicious `overrides.json` files that could be automatically loaded.
