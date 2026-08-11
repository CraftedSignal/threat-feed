---
title: Directory Traversal and LFI in Ray 2.56.0
slug: 2026-08-ray-traversal
description: Ray 2.56.0 contains a directory traversal and local file inclusion vulnerability in the /api/v0/logs endpoint allowing unauthenticated attackers to read arbitrary files.
date: "2026-08-11T14:06:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - directory-traversal
  - lfi
vendors:
  - Ray Project
products:
  - Ray (2.56.0)
affected_os:
  - Ubuntu 22.04
  - RHEL 10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: By supplying a crafted glob filter, a remote unauthenticated attacker can access files outside the intended log directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The proof of concept demonstrates a directory traversal/local file inclusion vulnerability in Ray's /logs API.
    confidence_band: med
references:
  - https://www.exploit-db.com/exploits/52635
  - https://github.com/ray-project/ray/issues/45751
  - https://github.com/ray-project/ray/pull/64701
rules:
  - title: Detect Ray API Directory Traversal Attempt
    description: Detects directory traversal attempts against the Ray /api/v0/logs endpoint by checking for traversal patterns in the glob parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for Ray API traversal detection.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public availability of functional exploit.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Ray dashboard.
      owner: IT Operations
      addresses: Ray 2.56.0
      evidence: Public exploit code allows unauthenticated access.
---

Ray version 2.56.0 contains a critical directory traversal and local file inclusion vulnerability within the /api/v0/logs API endpoint. The vulnerability allows an unauthenticated remote attacker to access files outside the intended log directory by supplying a crafted glob filter via the 'glob' parameter. An attacker must possess a valid node_id to interact with the API successfully. This vulnerability has been documented with a functional proof-of-concept exploit which demonstrates the ability to read sensitive files from the underlying host filesystem, such as those within /etc. Ray maintainers have been notified, and a fix is currently under review in GitHub Pull Request 64701.

## Attack Chain

1. Attacker performs reconnaissance to identify Ray dashboard instances accessible over the network, typically on port 6379.
2. Attacker probes the environment to enumerate or discover a valid node_id required for interaction with the /api/v0/logs endpoint.
3. Attacker crafts an HTTP GET request to the /api/v0/logs endpoint.
4. Attacker includes the 'node_id' parameter with the discovered identifier.
5. Attacker injects a malicious traversal payload into the 'glob' parameter, such as '../../../../etc/*'.
6. The Ray API processes the glob pattern without sufficient validation, concatenating the malicious path.
7. The application returns the contents of the requested file or directory within the HTTP response body.
8. Attacker successfully exfiltrates sensitive files from the server's filesystem.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files on the system running Ray, potentially leading to the exposure of credentials, configuration files, or other sensitive system data. The vulnerability is confirmed to affect Ubuntu 22.04 and RHEL 10.0 deployments.

## Recommendation

- Implement network access controls to restrict access to the Ray dashboard (default port 6379) to authorized internal networks only.
- Monitor webserver logs for HTTP GET requests to '/api/v0/logs' containing directory traversal characters (e.g., '../') in the 'glob' parameter.
- Deploy the Sigma rule provided in this brief to identify exploitation attempts against the logs API.
- Apply the vendor-provided patch once released via the official Ray project repository (GH PR 64701).
