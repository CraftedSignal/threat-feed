---
title: NocoBase Authenticated Remote Code Execution via File Write and LFI Chain
slug: 2026-08-nocobase-rce
description: An authenticated admin can achieve remote code execution in NocoBase prior to v2.1.5 by chaining arbitrary file uploads via storage root manipulation with a local file inclusion vulnerability in the plugin manager.
date: "2026-08-20T19:13:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - lfi
  - nocobase
  - authentication-bypass
vendors:
  - NocoBase
products:
  - '@nocobase/server (< 2.1.5)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attacker can leverage an unsanitized 'filterByTk' parameter in the 'pm:enable' endpoint to perform a Local File Inclusion (LFI) attack, which triggers a Node.js 'require()' call on the previously uploaded arbitrary file.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The payload writes output to the NocoBase uploads directory, which is served statically, and executes as Node.js code.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-ghvf-qf6h-g8x5
rules:
  - title: Detect NocoBase LFI and RCE Attempt
    description: Detects unauthorized attempts to trigger require() on arbitrary files via the NocoBase pm:enable endpoint
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade @nocobase/server to version 2.1.5 or later.
      owner: IT Operations
      due: 48h
      evidence: NocoBase versions prior to 2.1.5 contain an authentication-based Remote Code Execution (RCE) vulnerability.
  hunt_leads:
    - lead: Search logs for unusual filterByTk parameters containing file paths in /api/pm:enable requests.
      technique_id: T1203
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The 'pm:enable' endpoint passes 'filterByTk' directly to the CLI runner with zero validation.
---

NocoBase versions prior to 2.1.5 contain a high-severity authentication-based remote code execution (RCE) chain. The vulnerability arises from two distinct flaws in the API surface that allow an authenticated administrative user to bypass file system protections. First, the `storages:update` API fails to validate the `documentRoot` parameter, enabling an attacker to redirect the application's file storage root to arbitrary locations on the host disk, including system or application directories. Second, the `pm:enable` endpoint performs an unsanitized `require()` call on a user-supplied `filterByTk` parameter, acting as a local file inclusion (LFI) primitive. By uploading a malicious JavaScript file to the application directory using the first vulnerability and subsequently triggering it via the LFI endpoint, an attacker can execute arbitrary code within the Node.js server process. The LFI primitive can also be exploited independently to induce error-based disclosure of sensitive system files.

## Attack Chain

1. Attacker authenticates to the NocoBase instance with administrative credentials.
2. Attacker queries the `/api/storages` endpoint to identify the `filterByTk` ID for the active local storage configuration.
3. Attacker sends a POST request to `/api/storages:update` with a crafted `documentRoot` parameter set to the application's root directory (e.g., ".").
4. Attacker uploads a malicious Node.js payload via the `/api/attachments:upload` endpoint, which is now saved to the application's base path due to the modified `documentRoot`.
5. Attacker calls the `/api/pm:enable` endpoint, supplying the path to the previously uploaded malicious file in the `filterByTk` parameter.
6. The application backend passes the unsanitized path directly to `require()`, executing the uploaded JavaScript payload.
7. The malicious code executes with the privileges of the NocoBase server process, achieving persistent RCE.

## Impact

Successful exploitation grants an authenticated attacker full remote code execution on the underlying host. Given that NocoBase often runs with elevated privileges (e.g., as root in default Docker configurations), this leads to a complete compromise of the application and the host server. Additionally, the LFI primitive allows for the unauthorized reading of sensitive files from the server's filesystem, facilitating further reconnaissance or credential theft.

## Recommendation

1. Immediately upgrade all NocoBase deployments to version 2.1.5 or later to resolve the missing input validation in the storage and plugin management components.
2. Audit administrative access logs for unauthorized access to the `storages:update` and `pm:enable` endpoints.
3. Restrict access to administrative API endpoints to trusted management networks.
4. Deploy the suggested Sigma rule to monitor for unusual `require()` activity originating from the plugin manager path.
