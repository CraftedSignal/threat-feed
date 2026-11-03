---
brief_id: brief-2026-11-03-suspicious-ide-extension-install
event_id: brief-2026-11-03-suspicious-ide-extension-install
revision: 1
activity_at: "2026-11-03T21:42:39Z"
title: Suspicious IDE Extension Installation via VSIX
slug: 2026-11-suspicious-ide-extension-install
description: Threat actors can gain persistence or code execution by sideloading malicious IDE extensions via the VSIX format, often triggered by script hosts or from volatile staging directories.
date: "2026-11-03T21:42:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - persistence
  - ide-extension
  - software-supply-chain
  - endpoint
vendors:
  - Microsoft
  - Cursor
  - VSCodium
  - Windsurf
products:
  - Visual Studio Code
  - Cursor
  - VSCodium
  - Windsurf
references:
  - https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/
  - https://code.visualstudio.com/docs/editor/extension-marketplace#_install-from-a-vsix
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/persistence_suspicious_ide_extension_vsix_install.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify IDE CLI --install-extension usage originating from script hosts or temp directories.
      technique_id: T1176.002
      data_needed:
        - Process creation events (Image, CommandLine, ParentProcessName)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detects installation of an IDE extension from a local VSIX when that path is in a staging directory, or the parent is a script host or installer.
  mitigation_plan:
    - priority: medium_term
      action: Enforce extension management policies to block sideloading or restrict source directories for extensions.
      owner: IT Operations
      addresses: T1176.002
      evidence: Sideloading a VSIX is a known way to persist or gain execution through a malicious IDE extension.
---

Attackers may exploit IDE sideloading capabilities by installing malicious extensions via the VSIX format. This activity involves invoking the command-line interface for editors such as Visual Studio Code, Cursor, VSCodium, or Windsurf with the --install-extension flag. Malicious activity is characterized by the execution of these installs from common staging directories (e.g., Temp, /tmp, /dev/shm) or when the parent process is a script interpreter such as PowerShell, Python, or Node.js, rather than the editor application itself.

## Impact

Successful exploitation allows for persistence within the developer environment or arbitrary code execution in the context of the user running the IDE. This may lead to credential theft, exfiltration of source code, or further compromise of the development workstation.

## Recommendation

- Implement monitoring for IDE CLI invocations using the --install-extension flag to identify sideloading activity.
- Review process lineage for IDE extension installations; prioritize investigation when the parent process is a script host or installer rather than the editor binary.
- Establish a policy for managing extension sources and restrict the installation of unapproved or externally sourced VSIX files.
- Conduct regular audits of installed IDE extensions to identify unauthorized or anomalous plugins.
- If a suspicious extension is identified, uninstall it, remove the associated VSIX file, and rotate sensitive credentials or tokens that may have been accessible to the extension.
