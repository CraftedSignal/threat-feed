---
title: Detection of Web Shells via Suspicious Double Extensions on Linux Servers
slug: 2026-09-linux-web-shell-double-extension
description: Attackers are observed using double-extension filenames (e.g., shell.php.jpg) to bypass file upload filters and achieve remote command execution or persistence on compromised Linux web servers.
date: "2026-09-11T12:49:34Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This rule identifies Linux web server processes creating files whose names combine a web-executable suffix with a misleading image, archive, script, or binary extension.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker exploiting an upload endpoint may write shell.php.jpg into a served directory.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The rule identifies patterns often used to conceal malicious content and bypass upload controls.
    confidence_band: med
rules:
  - title: Detect File with Suspicious Double Extension Created by Web Server
    description: Detects web server processes creating files with a web-executable suffix followed by a misleading non-web extension, a common technique for web shell deployment.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule for detecting double-extension file creation by web server processes.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 5fc7e978-4fa0-47e9-a8e0-bad853c8d09b
  hunt_leads:
    - lead: Search for files within web directories ending in .jpg, .png, or .zip that contain suspicious file headers or script content.
      technique_id: T1505.003
      data_needed:
        - File system enumeration logs
        - MIME type/magic byte inspection
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source recommends identifying suspicious file contents for forensic analysis.
---

This threat involves the use of deceptive file naming conventions to achieve persistence and command execution on Linux-based web servers. Attackers exploit vulnerabilities in web application file upload mechanisms by submitting files that contain both a server-side executable extension (such as .php or .jsp) and a seemingly benign file extension (such as .jpg or .zip). If the server is misconfigured or lacks proper MIME type validation, the web server process may execute the uploaded file as a script despite the misleading final extension. This technique is frequently utilized to install web shells, enabling attackers to maintain persistent remote access, exfiltrate data, or pivot to internal network resources. Defenders must monitor for file creation events originating from web server processes that exhibit this specific naming pattern within web-accessible directories.

## Attack Chain

1. Attacker identifies a public-facing web application with an insecure file upload endpoint.
2. Attacker crafts a web shell payload disguised with a double extension (e.g., webshell.php.jpg).
3. Attacker submits the malicious file via an HTTP POST request to the application upload handler.
4. Web server application process receives the request and writes the file to the web root or a storage directory.
5. Attacker sends a secondary HTTP request to the location of the uploaded file.
6. Web server configuration (e.g., misconfigured handler or rewrite rule) triggers execution of the script despite the final .jpg extension.
7. Web shell executes, providing the attacker with persistent remote command execution capabilities.

## Impact

Successful exploitation allows for full system compromise of the affected web server. Impact includes unauthorized remote access, potential data exfiltration, and the ability to use the compromised server as a foothold for lateral movement into the internal network. The technique is a common precursor to wider infrastructure breach, often seen in the deployment of follow-on malicious tooling.

## Recommendation

Prioritize the implementation of robust file validation and server hardening to prevent the execution of malicious uploads.
- Deploy the provided Sigma rule to detect file creation events where web server processes generate files with double extensions.
- Configure web server handlers to explicitly deny execution of files that do not strictly match intended executable extensions.
- Enforce strict allowlists for file uploads and ensure uploaded content is stored outside of web-accessible document roots.
- Review web server configurations for permissive handler settings that may inadvertently execute files based on partial naming matches.
- Implement periodic integrity monitoring for files within web-accessible directories to identify unauthorized persistence mechanisms.
