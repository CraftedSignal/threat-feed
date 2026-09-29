---
title: Path Traversal Vulnerability in VLC media player skins2 ThemeLoader
slug: 2026-09-vlc-path-traversal
description: VLC media player versions prior to 3.0.24 contain a path traversal vulnerability in the skins2 component, allowing attackers to overwrite arbitrary files and achieve code execution via malicious .vlt skin archives.
date: "2026-09-29T20:29:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - code-execution
  - path-traversal
vendors:
  - VideoLAN
products:
  - VLC media player (< 3.0.24)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can craft malicious skin files with path traversal sequences to write arbitrary files with VLC user privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: enabling code execution through Lua script injection.
    confidence_band: high
cves:
  - id: CVE-2026-102875
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102875
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade VLC media player to version 3.0.24 or later.
      owner: IT Operations
      addresses: CVE-2026-102875
      evidence: VLC media player before 3.0.24 contains a path traversal vulnerability.
---

VLC media player versions before 3.0.24 are susceptible to a path traversal vulnerability located within the skins2 ThemeLoader module. The vulnerability arises from improper validation of member names within .vlt skin archive files. An attacker can create a specially crafted .vlt archive containing path traversal sequences, such as dot-dot-slash (../) patterns, to escape the intended directory during the extraction process. By successfully exploiting this, a threat actor can write files to arbitrary locations on the host filesystem with the permissions of the user running the application. This mechanism can be leveraged to achieve remote code execution by overwriting or placing malicious Lua scripts in paths where the application or the user session executes code.

## Impact

Successful exploitation allows for arbitrary file write operations, which can lead to remote code execution on the affected host. This affects all users running VLC media player versions prior to 3.0.24 on Windows, Linux, or macOS. If compromised, the integrity of the local user environment is at risk, potentially leading to full system compromise depending on the user's privilege level.

## Recommendation

Update all installations of VLC media player to version 3.0.24 or later immediately. Users should exercise caution when importing or applying third-party skin files from untrusted sources.
