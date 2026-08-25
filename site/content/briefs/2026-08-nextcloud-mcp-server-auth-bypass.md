---
title: Unauthenticated Vector Data Deletion in nextcloud-mcp-server via CVE-2026-55640
slug: 2026-08-nextcloud-mcp-server-auth-bypass
description: An unauthenticated remote attacker can delete or corrupt semantic search vector embeddings in Qdrant by sending a crafted POST request to the /webhooks/nextcloud endpoint due to missing default authentication.
date: "2026-08-25T18:48:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Nextcloud
products:
  - nextcloud-mcp-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The nextcloud-mcp-server application fails to enforce authentication on the /webhooks/nextcloud endpoint when the WEBHOOK_SECRET configuration is unset.
    confidence_band: high
cves:
  - id: CVE-2026-55640
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-8vh3-g2qg-2h2c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55640
rules:
  - title: Detects CVE-2026-55640 Exploitation - Unauthenticated Webhook POST
    description: Detects unauthenticated POST requests to the /webhooks/nextcloud endpoint, which indicates potential CVE-2026-55640 exploitation attempts.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify unauthenticated requests to /webhooks/nextcloud.
      owner: Detection Engineering
      due: 24h
      evidence: Source explicitly identifies missing authentication as the root cause.
  mitigation_plan:
    - priority: immediate
      action: Patch nextcloud-mcp-server to latest version and enforce WEBHOOK_SECRET in configuration.
      owner: IT Operations
      addresses: CVE-2026-55640
      evidence: Source recommends secret enforcement and code-level rejection.
---

The `nextcloud-mcp-server` application, specifically versions 0.117.1 and earlier, contains a critical authentication bypass vulnerability (CVE-2026-55640). The webhook receiver endpoint at `POST /webhooks/nextcloud` fails to enforce security checks by default because the `WEBHOOK_SECRET` configuration variable is not required at startup and defaults to `None`. 

When this secret is unset, the server skips all authentication validation and proceeds to process incoming JSON payloads. An attacker can supply an arbitrary `user.uid` within the payload, which the server then uses to interact with the backend Qdrant database. This allows unauthorized parties to manipulate or delete vector embeddings associated with any user index. This vulnerability is significant as it requires no prior authentication or system access, and can be used to perform mass-deletion attacks, effectively destroying the semantic search capabilities of the target Nextcloud instance.

## Attack Chain

1. Attacker performs network reconnaissance to identify instances of `nextcloud-mcp-server` listening on port 8000.
2. Attacker verifies the target is running a vulnerable version (<= 0.117.1) where `WEBHOOK_SECRET` is unset.
3. Attacker crafts a malicious JSON payload formatted as an `OCP\Files\Events\Node\BeforeNodeDeletedEvent` webhook.
4. Attacker inserts a target `user.uid` and specific document ID into the JSON payload fields.
5. Attacker sends an unauthenticated `POST` request to `/webhooks/nextcloud` targeting the reachable endpoint.
6. The server application accepts the request due to the missing secret validation and passes the attacker-controlled `user_id` to the Qdrant database client.
7. The Qdrant backend executes the delete operation, removing the specific vector embeddings for the chosen user and document.
8. Attacker repeats this process across multiple document IDs or users to disrupt semantic search services (Denial of Service).

## Impact

Successful exploitation allows unauthenticated attackers to delete or corrupt the entire semantic search index for all users within the affected Qdrant instance. This results in a complete loss of search functionality, requiring costly recovery and re-indexing operations. The vulnerability affects any deployment that has not explicitly configured a `WEBHOOK_SECRET`, which is the default state for the application.

## Recommendation

1. Upgrade `nextcloud-mcp-server` to the latest secure version immediately.
2. Enforce the `WEBHOOK_SECRET` configuration by adding a validation check in `config_validators.py` that raises a `ConfigurationError` if the secret is unset when vector sync is enabled.
3. Update `webhook_receiver.py` to reject all incoming requests with a 503 or 401 error code if the `WEBHOOK_SECRET` is not provided and validated via an HMAC-protected Authorization header.
4. Monitor web server logs for high volumes of `POST` requests to `/webhooks/nextcloud` originating from untrusted network segments.
