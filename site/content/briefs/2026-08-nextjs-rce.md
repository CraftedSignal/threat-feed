---
title: Unauthenticated Remote Command Execution in Next.js on Windows
slug: 2026-08-nextjs-rce
description: A critical path traversal vulnerability (CVE-2026-75604) in the Next.js FileSystemCache on Windows allows unauthenticated attackers to steal Server Action encryption keys and execute arbitrary commands.
date: "2026-08-26T13:04:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - rce
  - path-traversal
  - windows
  - nextjs
vendors:
  - Vercel
products:
  - Next.js (13.4 to 15.5.23)
  - Next.js (16.0.0 to 16.3.2)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Next.js on Windows via FileSystemCache traversal stealing Server Action key.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: By reading the sensitive server-reference-manifest.json file, an attacker can steal the Server Action encryption key to forge requests and execute arbitrary system commands.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75604
  - https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36
rules:
  - title: Detect CVE-2026-75604 Exploitation Attempt - Path Traversal
    description: Detects exploitation attempts against Next.js utilizing path traversal sequences targeting the FileSystemCache to retrieve manifest files.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Next.js to 15.5.24 or 16.3.3
      owner: IT Operations
      due: 24h
      evidence: Verified fixed versions provided in official advisory
  mitigation_plan:
    - priority: immediate
      action: Block requests containing ..%5C at the WAF or ingress gateway
      owner: Network Security
      addresses: CVE-2026-75604
      evidence: Path traversal via encoded backslash is the primary exploit vector
---

CVE-2026-75604 is a critical vulnerability affecting Next.js applications hosted on Windows environments. The flaw originates in the `FileSystemCache` component, which fails to correctly identify backslashes (`\`) as path separators on Windows systems. This improper validation enables path traversal attacks via the `..%5C` sequence. An unauthenticated attacker can exploit this to access the sensitive `server-reference-manifest.json` file, which contains the `encryptionKey` used for Server Actions. Possession of this key allows an attacker to forge legitimate-looking, closure-based Server Action requests. When these forged requests are processed by the server, they lead to unauthenticated remote command execution (RCE) on the underlying host. The vulnerability specifically impacts configurations that utilize both the Pages Router and the App Router without Cache Components enabled.

## Attack Chain

1. Attacker identifies a Windows-hosted Next.js application using both Pages and App Routers.
2. Attacker crafts a malicious HTTP request containing the `..%5C` traversal sequence.
3. The request exploits the `FileSystemCache` path parsing flaw to bypass cache directory constraints.
4. The application improperly returns the contents of the `server-reference-manifest.json` file.
5. Attacker parses the response to extract the `encryptionKey` used for signing Server Actions.
6. Attacker signs a malicious Server Action payload using the stolen `encryptionKey`.
7. Attacker submits the forged Server Action request to the target application.
8. The Next.js application executes the attacker-supplied command within the server-side runtime, resulting in full system compromise.

## Impact

Successful exploitation results in full unauthenticated remote command execution on the host server. Given the nature of Server Actions, attackers can gain code execution with the privileges of the service account running the Next.js application. This impacts any enterprise organization running Next.js versions between 13.4 and 15.5.23 or 16.0.0 and 16.3.2 on Windows platforms.

## Recommendation

* Immediately patch all instances of Next.js to versions `15.5.24` or `16.3.3` to remediate CVE-2026-75604.
* Inspect web server logs for HTTP requests containing the `..%5C` traversal string directed at cache-related endpoints.
* Monitor for abnormal child processes spawned by the web application service account (e.g., `cmd.exe`, `powershell.exe`).
* Review configuration files for any instances where Pages and App Routers coexist without explicit Cache Component definitions.
