---
title: Unauthenticated AetherBrowser API Exposes Operator Email Metadata
slug: 2026-09-aetherbrowser-unauth-api
description: An unauthenticated API endpoint in SCBE-AETHERMOORE AetherBrowser allows remote attackers to trigger the execution of a subprocess that retrieves and exposes operator email metadata from IMAP accounts.
date: "2026-09-26T02:06:58Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - SCBE-AETHERMOORE
products:
  - AetherBrowser (4.2.1)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The endpoint triggers the email_reader.py subprocess, which connects to configured ProtonMail or Gmail accounts via IMAP to retrieve email metadata.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The API server invokes _run_subprocess to execute email_reader.py, which fetches and returns email metadata via stdout.
    confidence_band: high
rules:
  - title: Detect Unauthenticated Access to AetherBrowser Ops API
    description: Detects unauthorized POST requests to the /api/ops/check-email endpoint on AetherBrowser API servers.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Deploy WAF or web server rule to block unauthenticated requests to /api/ops/check-email
      owner: Security Operations
      due: 24h
      evidence: Source documentation of unauthenticated API path
  mitigation_plan:
    - priority: immediate
      action: Apply the provided dependency patch to require API-key authentication on /api/ops/ routes
      owner: IT Operations
      addresses: CWE-306 Missing Authentication
      evidence: Remediation section of the source
---

The SCBE-AETHERMOORE AetherBrowser API server, specifically in version 4.2.1, includes a critical information-disclosure vulnerability within `scripts/aetherbrowser/api_server.py`. The `POST /api/ops/check-email` endpoint is exposed without any authentication or authorization mechanisms, such as API-key validation or middleware access guards. By default, the application binds to all interfaces (`0.0.0.0:8100`) and is configured with wildcard CORS (`allow_origins=["*"]`), making it accessible to any network-connected actor.

When invoked, the endpoint triggers the execution of `email_reader.py` as a subprocess. This script automatically attempts to load credentials from `config/connector_oauth/.env.connector.oauth` and initiates IMAP connections to configured ProtonMail or Gmail accounts. The API server captures the standard output of this process, which includes sender information, subjects, and body snippets of fetched RFC822 messages, and returns this sensitive data to the caller in a JSON response. This provides a mechanism for unauthorized actors to exfiltrate operational intelligence without requiring credentials or prior access to the host environment.

## Attack Chain

1. Attacker performs network scanning to identify reachable instances of AetherBrowser listening on port 8100.
2. Attacker crafts a standard HTTP POST request to the `/api/ops/check-email` endpoint.
3. The `api_server.py` processes the request, bypassing authentication checks due to the missing `Depends()` decorator.
4. The server executes `email_reader.py` as a system subprocess (`_run_subprocess`).
5. The `email_reader.py` script parses local environment files to retrieve configured IMAP credentials.
6. The script establishes an IMAP connection to the target mail provider (ProtonMail or Gmail) using the retrieved credentials.
7. The script fetches RFC822 messages, parses them, and writes email metadata to stdout.
8. The API server intercepts the first 2000 characters of stdout and returns the email data to the attacker in the HTTP response.

## Impact

Successful exploitation allows unauthenticated remote attackers to exfiltrate email metadata, including sender identities, subjects, and content snippets. This disclosure of sensitive operational communications can facilitate follow-on social engineering or targeted attacks against operators. Additionally, repeated calls to the endpoint can lead to IMAP connection exhaustion or account-level security alerts, effectively disclosing the operational infrastructure's mail configuration and diagnostic status.

## Recommendation

1. Patch immediately by implementing mandatory API-key validation using a header-based check (e.g., `X-API-KEY`) for all `/api/ops/*` endpoints.
2. Modify the API server configuration to bind only to `127.0.0.1` to prevent remote access unless explicitly required by the architecture.
3. Disable wildcard CORS (`allow_origins=["*"]`) and restrict access to specific, trusted origins.
4. Implement strict input and output sanitization for subprocess interactions; the application should not return raw stdout from operational scripts to external API callers.
5. Rotate all mail credentials stored in `config/connector_oauth/.env.connector.oauth` if it is suspected that the API was exposed to untrusted networks.
