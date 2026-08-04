---
title: Remote Code Execution in Flowise via TypeORM Configuration
slug: 2026-08-flowise-rce
description: Authenticated users can exploit improper validation of TypeORM DataSource configurations in FlowiseAI <= 3.1.2 to achieve remote code execution by loading arbitrary local JavaScript files.
date: "2026-08-04T17:24:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - injection
  - flowise
  - typeorm
vendors:
  - FlowiseAI
products:
  - Flowise (<= 3.1.2)
  - flowise-components (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to load and execute arbitrary local JavaScript files via the TypeORM DataSource.
    confidence_band: high
cves:
  - id: CVE-2026-69251
references:
  - https://github.com/advisories/GHSA-g32j-mmxr-gfq5
  - https://typeorm.io/docs/data-source/data-source
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Flowise to the latest version and perform an audit of all active chatflows.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-69251
---

FlowiseAI version 3.1.2 and earlier contains a critical remote code execution (RCE) vulnerability identified as CVE-2026-69251. The flaw resides in how specific record manager and memory nodes - including MySQLRecordManager, PostgresRecordManager, and SQLiteRecordManager - handle user-supplied inputs within the `additionalConfig` parameter. This parameter allows for the configuration of the TypeORM `DataSource` class, which supports loading local files as JavaScript. An authenticated attacker can upload a malicious JavaScript file via the document store and subsequently reference this file within the `entities`, `subscribers`, or `migrations` fields of the node configuration. When the node performs an upsert or related database operation, the application executes the injected code, bypassing the `vm2` sandbox. This vulnerability grants attackers full control over the host system with the privileges of the Flowise process.

## Attack Chain

1. The attacker authenticates to the Flowise instance via `POST /api/v1/auth/login` to obtain a session token.
2. The attacker uses the File Loader endpoint to upload a malicious JavaScript payload (e.g., a reverse shell) to the server.
3. The attacker retrieves the `storeId` of the uploaded file by monitoring the response from `POST /api/v1/document-store/loader/process/{loader_id}`.
4. The attacker imports a chatflow containing vulnerable nodes, such as the MySQL Record Manager.
5. The attacker configures the "Additional Parameters" of the target node, specifically setting the `entities` field to the absolute file path of the previously uploaded malicious JavaScript file.
6. The attacker triggers an upsert operation within the Flowise interface.
7. The application backend processes the `DataSource` options and loads the attacker-supplied JavaScript file as a TypeORM entity.
8. The payload executes on the server, resulting in RCE and full application compromise.

## Impact

Successful exploitation results in full remote code execution on the server running the Flowise instance. As observed in laboratory environments, an attacker can gain root-level shell access if the container or application is running with elevated privileges. This vulnerability affects all instances using Flowise version 3.1.2 or older, posing a risk to any organization deploying the low-code platform for AI application development.

## Recommendation

1. Immediately upgrade Flowise and flowise-components to a version that implements input validation for the `additionalConfig` parameter to prevent the injection of dangerous TypeORM options.
2. Audit all existing chatflows and node configurations for suspicious paths in `entities`, `subscribers`, or `migrations` fields.
3. Deploy detection logic to monitor webserver access logs for anomalous `POST` requests to document loader endpoints followed by configuration updates in the API.
4. Implement strict network egress filtering on the host machine to prevent unauthorized reverse shells or C2 traffic, particularly for containers running Flowise.
