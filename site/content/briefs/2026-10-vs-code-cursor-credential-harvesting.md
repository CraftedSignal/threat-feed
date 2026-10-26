---
brief_id: brief-2026-10-26-vs-code-cursor-credential-harvesting
event_id: brief-2026-10-26-vs-code-cursor-credential-harvesting
revision: 1
activity_at: "2026-10-26T22:21:29Z"
title: 'VS Code and Cursor: Credential harvesting by IDE extensions'
slug: 2026-10-vs-code-cursor-credential-harvesting
description: Malicious extensions or compromised IDE agents may use VS Code or Cursor process trees to exfiltrate multiple sensitive credential stores from a developer workstation.
date: "2026-10-26T22:21:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Analysis performed against Elastic detection rule logic
tags:
  - credential-access
  - persistence
  - ide
  - supply-chain
vendors:
  - Microsoft
  - Cursor
products:
  - Visual Studio Code
  - Cursor
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Malicious IDE extensions use the editor process tree to harvest more than one credential store in a single session.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    subtechnique_id: T1555.003
    subtechnique_name: Credentials from Web Browsers
    evidence: The files include browser stores (logins.json, Login Data, Cookies), cloud and token files.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_multiple_files_by_vscode_or_cursor_descendant.toml
  - https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection logic targeting IDE descendant processes opening multiple credential-related files
      owner: Detection Engineering
      due: 48h
      evidence: Elastic detection rule f27228e4-0792-4681-a965-9937ed6e4e00
  hunt_leads:
    - lead: Identify processes with VS Code/Cursor parentage opening multiple sensitive files (e.g., .npmrc, credentials.toml, logins.json)
      technique_id: T1552.001
      data_needed:
        - Endpoint process creation and file access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule logic requires unique_sensitive_files >= 2
  mitigation_plan:
    - priority: medium
      action: Enforce organizational allow-list for IDE extensions
      owner: IT Operations
      addresses: T1176.002
      evidence: IDE Extensions are a known vector for credential harvesting
---

Extensions and sub-processes associated with Visual Studio Code and Cursor IDEs are being observed accessing multiple distinct sensitive files in a single session. This behavior is symptomatic of credential harvesting, potentially performed by malicious IDE extensions or agents manipulated through prompt injection. The access targets browser credential stores, cloud access tokens, and SSH or package manager configuration files.

## Attack Chain

1. An attacker publishes a malicious IDE extension or compromises an existing one.
2. The target developer installs or updates the malicious extension.
3. The extension is executed within the context of the IDE process tree (e.g., `extensionHost`).
4. The malicious extension or a sub-process spawned by the IDE attempts to open sensitive files.
5. The attacker iterates through multiple credential stores (e.g., cookies, SSH keys, `.npmrc`).
6. The retrieved data is exfiltrated or utilized to escalate privileges in cloud environments.

## Impact

Successful exploitation results in the unauthorized exfiltration of locally stored developer secrets, including browser-based credentials, cloud infrastructure tokens, and SSH keys. This enables lateral movement, persistent access to code repositories, and potential compromise of connected cloud infrastructure.

## Recommendation

- Audit installed extensions in VS Code and Cursor for unauthorized or suspicious publishers.
- Implement monitoring for processes spawned by IDE processes that attempt to access multiple sensitive credential stores.
- For incident responders: If suspicious access is detected, isolate the host, rotate all credentials identified in accessed files, and audit recent IDE extension installations.
- Establish a policy requiring developers to review extension permissions before installation.
