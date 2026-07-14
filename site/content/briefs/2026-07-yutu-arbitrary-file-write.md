---
title: Arbitrary File Write in Yutu's MCP caption-download Tool (CVE-2026-50158)
slug: 2026-07-yutu-arbitrary-file-write
description: An arbitrary file write vulnerability (CVE-2026-50158) in the `caption-download` MCP tool of the yutu application allows a local attacker, or any process able to reach the unauthenticated HTTP MCP server, to bypass the `YUTU_ROOT` confinement and write arbitrary content to any path writable by the yutu process, leading to potential persistent code execution, privilege escalation, or denial of service.
date: "2026-07-14T19:42:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-write
  - cve
  - golang
  - local-privilege-escalation
  - persistence
vendors:
  - eat-pray-ai
products:
  - yutu (< 0.10.9-dev1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Overwriting application binaries, configuration files, or shell startup scripts to achieve persistent code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any principal that can invoke the caption-download MCP tool [...] can write attacker-controlled bytes to any file path accessible to the yutu process.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Corrupting log files or database files to cause denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2c7f-fxww-6w6c
---

The yutu application, developed by eat-pray-ai, contains a high-severity arbitrary file write vulnerability, tracked as CVE-2026-50158. This flaw resides within the `caption-download` MCP tool, where the `file` parameter, provided by the caller, is passed directly to the `os.Create()` function without proper path validation or confinement to the intended `YUTU_ROOT` directory. This bypasses the security boundary implemented by Go's `os.OpenRoot` that other file operations respect. An attacker, either local or via an unauthenticated HTTP MCP server (the default configuration), can exploit this to write arbitrary content to any location on the filesystem accessible to the yutu process. This critical oversight can lead to persistent code execution by overwriting startup scripts or application binaries, privilege escalation if yutu runs with elevated privileges, or denial of service through the corruption of critical system files. The vulnerability affects yutu versions prior to 0.10.9-dev1.

## Attack Chain

1. An attacker, either a local process or a remote entity (if the HTTP MCP server is exposed and unauthenticated), crafts a malicious JSON-RPC request.
2. The attacker sends this request via HTTP POST to the yutu MCP server's `/mcp` endpoint, typically running on `http://localhost:8216`.
3. The JSON request body specifies the `"method":"tools/call"` and targets the `"name":"caption-download"` tool.
4. Within the `arguments` of the `caption-download` tool, the attacker provides a manipulated `file` parameter containing an absolute path (e.g., `"/etc/passwd"`, `"/tmp/evil_script.sh"`) that points outside the intended `YUTU_ROOT` confinement.
5. The yutu MCP server processes the request, and the `cobramcp.GenToolHandler` binds the attacker's input to the `caption.Download()` function.
6. Inside `caption.Download()`, the vulnerable code at `pkg/caption/caption.go:272` uses `os.Create(c.File)` directly, passing the unvalidated, attacker-controlled file path. This call bypasses the `pkg.Root` boundary, which would normally restrict file operations.
7. Subsequently, the downloaded caption bytes (which can be attacker-controlled or from a legitimate source) are written to the specified arbitrary file path, resulting in an arbitrary file write.
8. This arbitrary file write can be leveraged to achieve various impacts, such as overwriting critical system files for persistence or privilege escalation, or corrupting data for denial of service.

## Impact

This arbitrary file write vulnerability (CVE-2026-50158) carries significant impact. Any entity capable of invoking the `caption-download` MCP tool, including an unauthenticated local process when the HTTP MCP server operates under default settings (`--auth false`), can write attacker-controlled data to any file path accessible by the yutu process. This directly bypasses the `YUTU_ROOT` confinement, which is designed to secure file operations. Potential consequences include overwriting application binaries, system configuration files, or shell startup scripts, which can lead to persistent code execution or privilege escalation. Corrupting log files or database files could result in a denial of service for the yutu application or other system components. Furthermore, in deployments where yutu runs alongside a web server, attackers might write web-accessible files to achieve further exploitation. The vulnerability could also be exploited through prompt injection if an AI agent pipeline exposes `caption-download` to untrusted input.

## Recommendation

* Patch CVE-2026-50158 immediately by upgrading yutu to version 0.10.9-dev1 or later, which incorporates the fix outlined in the GHSA advisory.
* Ensure the yutu MCP server is configured with authentication enabled if remote access is required, preventing unauthenticated access to the `caption-download` tool.
* Restrict network access to the yutu MCP server (`http://localhost:8216`) to only trusted internal processes or local applications, minimizing the attack surface for remote exploitation.
