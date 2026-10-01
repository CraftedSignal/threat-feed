---
title: JupyterLab Cross-Site Scripting via System Clipboard
slug: 2026-10-jupyterlab-xss
description: JupyterLab is vulnerable to a cross-site scripting (XSS) attack via the system clipboard that allows unauthorized JavaScript execution within the user's session when pasting cells from an external source.
date: "2026-10-01T20:22:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jupyter:jupyterlab:*:*:*:*:*:*:*:*
vendors:
  - Jupyter
products:
  - JupyterLab (4.5.0-4.6.3)
  - Notebook (7.5.0-7.6.2)
  - JupyterLite (0.7.0-0.8.3)
  - JupyterLite Core (0.7.0-0.8.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: JupyterLab does not sanitize a trusted output and evaluates the <script> elements it contains, so pasting the cell runs attacker's JavaScript in the JupyterLab origin.
    confidence_band: high
cves:
  - id: CVE-2026-102831
    cvss: 8.1
    epss: 0.00196
references:
  - https://github.com/advisories/GHSA-6966-vjj6-99xv
  - https://github.com/jupyterlab/jupyterlab/releases/tag/v4.6.4
  - https://github.com/jupyterlab/jupyterlab/releases/tag/v4.5.11
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch JupyterLab to v4.6.4 or v4.5.11 across all development and production environments
      owner: IT Operations
      due: 24h
      evidence: Patches for CVE-2026-102831 were released in these versions.
  mitigation_plan:
    - priority: immediate
      action: Disable system clipboard for JupyterLab cells via configuration settings
      owner: IT Operations
      addresses: CVE-2026-102831
      evidence: Workaround documentation provided by the vendor.
---

JupyterLab versions 4.5.0 through 4.6.3 contain a security vulnerability (CVE-2026-102831) that enables cross-site scripting (XSS) via the system clipboard. The vulnerability exists in the paste mechanism, which parses clipboard text as JSON for cell data. Crucially, the application fails to strip the `metadata.trusted` field from imported cell content. An attacker can supply a malicious JSON payload in the system clipboard that labels a cell's output as trusted. Because JupyterLab does not sanitize trusted output, any embedded `<script>` elements are executed within the JupyterLab origin.

The attack is highly impactful as it executes arbitrary JavaScript in the context of an authenticated user's active session. This allows for unauthorized interaction with the Jupyter Server REST API, enabling actions such as reading or writing files within the server root, spawning kernels, or interacting with terminals. Exploitation does not require prior access to the target system, only that a user pastes content into a vulnerable JupyterLab instance while the attacker-controlled payload resides in the clipboard.

## Attack Chain

1. Attacker hosts a webpage containing malicious code designed to populate a user's system clipboard upon interaction (e.g., clicking a button).
2. The attacker-controlled clipboard content is populated with a crafted JSON array representing a Jupyter notebook cell, containing `{"metadata": { "trusted": true }}` and a malicious `<script>` payload within the output field.
3. The victim visits the malicious webpage and interacts with it, granting the page access to write to the system clipboard.
4. The victim switches to an active, authenticated JupyterLab session in their browser.
5. The victim performs a paste action (via menu, palette, or shortcut) while the malicious payload is in the system clipboard.
6. JupyterLab parses the JSON, respects the `metadata.trusted` flag, and renders the untrusted output.
7. The browser executes the attacker's JavaScript within the JupyterLab origin.
8. The malicious script makes unauthorized requests to the Jupyter Server REST API to exfiltrate files or execute arbitrary commands.

## Impact

Successful exploitation results in full session compromise within the Jupyter environment. An attacker can read, modify, or delete any file accessible to the Jupyter process, execute arbitrary commands via kernel interaction, or gain shell access if terminals are enabled. Affected products include JupyterLab, Jupyter Notebook 7.5.0-7.6.2, and JupyterLite 0.7.0-0.8.3. This vulnerability significantly impacts research and development environments where JupyterLab is deployed to process sensitive data or credentials.

## Recommendation

1. Upgrade JupyterLab to version 4.6.4 or 4.5.11 immediately.
2. For applications bundling JupyterLab, such as Notebook v7+, upgrade the underlying `jupyterlab` package to a patched version.
3. If immediate upgrading is not possible, set `@jupyterlab/notebook-extension:tracker:useSystemClipboardForCells` to `false` in the settings to disable system clipboard pasting for cells.
4. As an additional mitigation, set `@jupyterlab/notebook-extension:tracker:pasteCodeCellsWithoutOutput` to `true` to ensure pasted cells do not contain the vulnerable output fields.
