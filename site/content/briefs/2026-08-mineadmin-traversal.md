---
title: MineAdmin Path Traversal in App Store Plugin Service
slug: 2026-08-mineadmin-traversal
description: MineAdmin versions before 3.2.0-alpha.2 contain a path traversal vulnerability in the app-store plugin service allowing authenticated attackers to interact with arbitrary file system directories.
date: "2026-08-18T20:57:14Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - MineAdmin
products:
  - MineAdmin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can use path traversal sequences (e.g., ../) to read, install, or uninstall plugins from arbitrary directories.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Plugin::install() with a traversed identifier may run composer commands on arbitrary directories.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-59xm-4m8c-g3xj
rules:
  - title: Detect CVE-2026-55224 Exploitation - Path Traversal in MineAdmin Plugin Service
    description: Detects path traversal attempts by checking for traversal sequences in the identifier parameter during plugin installation
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch all MineAdmin instances to version 3.2.0-alpha.2 or newer.
      owner: IT Operations
      due: 48h
      evidence: Source remediation guidance.
    - action: Deploy Sigma detection rule to monitor for traversal attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Provided rule ensures visibility into exploit attempts.
---

MineAdmin versions prior to 3.2.0-alpha.2 are vulnerable to a path traversal vulnerability in the app-store plugin service, tracked as CVE-2026-55224. The vulnerability arises because the `identifier` parameter in the `download`, `install`, and `unInstall` functions is concatenated directly into file system paths without adequate sanitization. An authenticated attacker can supply path traversal sequences, such as '../', to interact with directories outside the intended plugin storage location.

The risk is exacerbated by the absence of proper authorization checks on the `admin/plugin/store` endpoint, as noted in related security findings (GM-4340). Successful exploitation could allow attackers to verify the existence of sensitive directories, perform arbitrary plugin operations, or potentially trigger composer-based command execution if the underlying `Plugin::install` functionality processes directories under the attacker's control. Defending organizations should update to version 3.2.0-alpha.2 or higher immediately to address this flaw.

## Attack Chain

1. Attacker obtains a valid JWT token via an existing authentication session.
2. Attacker crafts a malicious HTTP POST request targeting the `admin/plugin/store/install` endpoint.
3. The `identifier` parameter is populated with traversal sequences (e.g., `../../etc`).
4. The application logic at `plugin/mine-admin/app-store/src/Service/Service.php` fails to validate the input.
5. The server resolves the traversed path to an arbitrary directory outside the `/plugin/` root.
6. The `Plugin::install` function is invoked with the attacker-controlled path.
7. The application executes file operations or command-line instructions within the traversed target directory.

## Impact

The vulnerability allows authenticated users to read file system structures and potentially escalate privileges via arbitrary code execution if the `Plugin::install` mechanism can be forced to execute composer commands against malicious directories. This affects all deployments of MineAdmin prior to version 3.2.0-alpha.2.

## Recommendation

* Patch MineAdmin to version 3.2.0-alpha.2 or higher to remediate CVE-2026-55224.
* Monitor webserver logs for POST requests to `/admin/plugin/store/` containing directory traversal sequences like `../` or `..\\`.
* Deploy the Sigma rule below to detect attempts to access arbitrary directories via the plugin install endpoint.
* Audit access logs for any authenticated user activity targeting the plugin store management endpoints.
