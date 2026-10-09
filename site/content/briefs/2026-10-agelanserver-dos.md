---
title: Unbounded JSON Array Allocation in ageLANServer Leads to Remote DoS
slug: 2026-10-agelanserver-dos
description: An unauthenticated remote denial-of-service vulnerability in ageLANServer allows attackers to trigger excessive memory consumption by sending crafted JSON arrays to the getFileURL endpoint.
date: "2026-10-09T21:25:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-exhaustion
  - json-injection
  - age-of-empires
vendors:
  - luskaner
products:
  - ageLANServer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The endpoint is reachable via the internet and vulnerable to pre-authentication exploitation.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: The exploitation leads to process termination via OOM killer, causing a loss of availability.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4jfq-pmq9-257h
rules:
  - title: Detect ageLANServer Unauthenticated Platform Login Spikes
    description: Detects high-frequency platform login attempts which may indicate session acquisition for DoS attacks.
    platform: sigma
    severity: medium
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update ageLANServer configuration to set Authentication to 'enabled'
      owner: IT Operations
      due: 24h
      evidence: Source states default configuration has Authentication disabled
  mitigation_plan:
    - priority: immediate
      action: Implement request size limiting via reverse proxy or application-level middleware
      owner: IT Operations
      addresses: Uncontrolled resource consumption
      evidence: Source identifies lack of MaxBytesReader as contributing factor
---

The ageLANServer application, specifically the `POST /game/cloud/getFileURL` endpoint, contains a critical vulnerability due to unbounded memory allocation based on attacker-supplied input. When the server processes the `names` JSON array, it performs a slice allocation using `make(i.A, len(req.Names.Data))` without enforcing any bounds on the array length or the HTTP request body size. By default, the application ships with `Authentication = 'disabled'`, allowing any network-reachable client to obtain a valid session identifier through the `platformlogin` flow without credentials. 

An attacker can exploit this by sending a specially crafted request containing a large number of elements in the `names` array, forcing the server to allocate memory proportional to the input. This behavior leads to massive memory amplification, effectively triggering the kernel OOM killer and crashing the server process. The vulnerability affects unmodified installations of the software as shipped in its default configuration.

## Attack Chain

1. The attacker identifies an internet-facing ageLANServer deployment.
2. The attacker sends a POST request to `/game/login/platformlogin` with arbitrary `accountType` and `platformUserID` parameters to obtain a `sessionID`.
3. The attacker constructs a malicious JSON payload with an oversized `names` array (e.g., millions of elements) encapsulated within a JSON string to bypass initial schema parsers.
4. The attacker sends the crafted payload in a `POST /game/cloud/getFileURL?sessionID=<id>` request to the server.
5. The `Bind()` function in `server/internal/http.go` parses the large request body into the `getFileURLRequest` struct without limiting the size of the input.
6. The `GetFileURL` handler in `server/internal/routes/game/cloud/getFileURL.go` extracts the length of the `names` array.
7. The application invokes `make()` using the attacker-controlled length, leading to immediate massive memory allocation.
8. The system memory is exhausted, triggering the kernel OOM killer and resulting in a service crash (Denial of Service).

## Impact

Successful exploitation results in a full process crash, rendering the game server unavailable to all legitimate players. Because the vulnerability is pre-authentication, no game ownership or valid credentials are required. Dynamic testing confirmed that concurrent requests can force OOM-killer termination of the process, ensuring consistent service disruption. This affects any environment where the server is exposed to untrusted networks.

## Recommendation

Prioritize the following remediation and detection actions to mitigate this risk:

* Apply input validation logic in `server/internal/routes/game/cloud/getFileURL.go` to enforce a hard cap on `len(req.Names.Data)` before memory allocation.
* Implement middleware using `http.MaxBytesReader` to limit the size of incoming HTTP request bodies across all endpoints.
* Disable the `Authentication = 'disabled'` setting in `server/resources/config/config.toml` to enforce mandatory session verification against real platform providers.
* Deploy the Sigma rules below to monitor for anomalous POST request sizes or high-frequency login activity indicating automated reconnaissance.
