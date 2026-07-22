---
title: JupyterLab Image Viewer XSS Vulnerability Leading to RCE
slug: 2026-07-jupyterlab-image-viewer-xss
description: A cross-site scripting (XSS) vulnerability exists in JupyterLab's image viewer, allowing an attacker to achieve remote code execution (RCE) on the JupyterLab server if a specially crafted image file is opened in the image viewer and then opened in a new browser tab; affected versions include JupyterLab prior to 4.5.10 and versions from 4.6.0 up to, but not including, 4.6.2, with patches available in versions 4.5.10 and 4.6.2.
date: "2026-07-22T23:15:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - rce
  - vulnerability
  - jupyterlab
  - web
vendors:
  - Jupyter
products:
  - JupyterLab (prior to 4.5.10)
  - JupyterLab (4.6.0 through 4.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: JupyterLab's image viewer allows for cross-site scripting (XSS) when a specially-crafted image file is opened through the image viewer and then opened in a new tab.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This XSS issue can be used to cause remote code execution (RCE) on the JupyterLab server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gx64-gj6p-pc4c
---

JupyterLab, an interactive development environment, contains a cross-site scripting (XSS) vulnerability within its image viewer component. This flaw allows an attacker to achieve remote code execution (RCE) on the JupyterLab server. The vulnerability is triggered when a specially crafted malicious image file is opened via the image viewer, and subsequently, the user opens this image in a new browser tab. Successful exploitation could lead to arbitrary code execution on the server hosting JupyterLab. The affected versions include JupyterLab prior to `4.5.10` and versions `4.6.0` up to, but not including, `4.6.2`. Patches are available in versions `4.5.10` and `4.6.2`. This is a high-severity issue because it transitions an XSS to RCE, providing a significant foothold for attackers.

## Attack Chain

1. **Craft Malicious Image**: An attacker crafts a specially designed image file containing embedded XSS payload.
2. **Deliver Image**: The malicious image is delivered to a target user, often through social engineering or by being placed in a location accessible to the JupyterLab user.
3. **User Opens Image in JupyterLab Viewer**: The user interacts with the malicious image by opening it within the JupyterLab image viewer.
4. **User Opens Image in New Tab**: The user then, as part of their workflow, opts to open the image from the viewer into a new browser tab.
5. **XSS Execution**: The malicious payload within the image is executed in the user's browser context due to the XSS vulnerability in the image viewer's new tab rendering.
6. **Remote Code Execution**: The executed XSS payload leverages the user's JupyterLab session privileges to perform actions, potentially leading to arbitrary command execution on the underlying JupyterLab server.
7. **Persistent Access/Data Exfiltration**: With RCE, the attacker can establish persistence, exfiltrate sensitive data from the JupyterLab environment or the host server, or further compromise the system.

## Impact

Successful exploitation of this vulnerability results in arbitrary code execution on the JupyterLab server. This grants attackers the ability to execute commands, potentially access or exfiltrate sensitive data, establish persistence within the environment, and further compromise the host system. Given that JupyterLab is often used for data science and development, this could expose intellectual property, sensitive research data, or grant access to development environments. The vulnerability affects any organization utilizing unpatched JupyterLab instances.

## Recommendation

* Patch JupyterLab to `v4.6.2` or `v4.5.10` immediately by upgrading your `pip/jupyterlab` installation to remediate the vulnerability.
* As a workaround if immediate patching is not possible, disable the image viewer plugin using the command `jupyter labextension disable @jupyterlab/imageviewer-extension:plugin`.
* Monitor JupyterLab server process creation logs and network connection logs for unusual activity that might indicate compromise, especially after user interactions with untrusted image files.
