---
title: Cross-Tenant IDOR in Convoy API Exposes Broker Credentials
slug: 2026-09-convoy-idor
description: Convoy versions up to and including 26.6.2 contain an Insecure Direct Object Reference (IDOR) vulnerability that allows authenticated users to leak plaintext message broker credentials from other tenants.
date: "2026-09-18T19:50:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:frain-dev:convoy:*:*:*:*:*:*:*:*
tags:
  - idor
  - credential-leak
  - api-security
vendors:
  - frain-dev
products:
  - convoy (<= 26.6.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows an authenticated user to access objects they are not authorized to view, effectively escalating their access to data belonging to other tenants.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The API endpoint returns plaintext broker credentials and full source configurations, facilitating the collection of sensitive victim information.
    confidence_band: high
cves:
  - id: CVE-2026-81505
references:
  - https://github.com/advisories/GHSA-p5vg-v7mj-f6q4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81505
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Security
  immediate_actions:
    - action: Review Convoy web access logs for suspicious enumeration patterns on the GetSource endpoint.
      owner: SOC
      due: 24h
      evidence: Source document identifies the vulnerable endpoint path as /api/v1/projects/{projectID}/sources/{sourceID}.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials managed within Convoy sources if the instance is exposed to potentially untrusted users.
      owner: Infrastructure Security
      addresses: CVE-2026-81505
      evidence: Source states that the API returns plaintext credentials verbatim.
---

Convoy (frain-dev/convoy) is affected by a cross-tenant Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-81505, which impacts all versions up to and including v26.6.2. The vulnerability exists within the `GetSource` API endpoint (`GET /api/v1/projects/{projectID}/sources/{sourceID}`). While the application correctly authorizes the caller against the `{projectID}` in the URL, the underlying database service `FindSourceByID` fails to filter the results by project ownership. 

An attacker with valid credentials for any project on a Convoy instance can supply the `sourceID` of a victim's configuration to retrieve the full, unredacted Source record. The response includes plaintext credentials for integrated message brokers, such as AMQP, Kafka, SQS, and Google PubSub. This flaw permits unauthorized cross-tenant information disclosure, allowing any authenticated user to harvest live secrets from other organizations using the same Convoy instance. No patch is currently available.

## Attack Chain

1. Attacker authenticates to a Convoy instance using valid credentials or a project-scoped API key.
2. Attacker identifies a target `{sourceID}` (e.g., through trial-and-error, enumeration, or information leakage).
3. Attacker constructs a malicious API request targeting the endpoint: `GET /api/v1/projects/{own_project_id}/sources/{target_source_id}`.
4. The Convoy API verifies that the user is authorized to access `{own_project_id}` and proceeds to the `GetSource` handler.
5. The `GetSource` handler calls `FindSourceByID` using the attacker-supplied `{target_source_id}`.
6. The backend SQL query `fetchSourceByID` ignores the project context and returns the requested record from the database.
7. The API serializes the entire `Source` object, including sensitive `pub_sub.*.auth.password` fields, into the JSON response.
8. Attacker parses the response to extract live broker credentials for unauthorized downstream access.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive message broker credentials, including AMQP, Kafka, SQS, and Google PubSub secrets. In multi-tenant environments, this constitutes a direct cross-customer credential leak. This impact is critical as it provides attackers with the ability to intercept, inject, or disrupt message traffic within the victim's infrastructure, potentially leading to further compromise of backend services or data exfiltration.

## Recommendation

1. Audit Convoy logs for excessive 200 OK responses to the `/api/v1/projects/*/sources/*` endpoint that correlate with user accounts accessing multiple different projects.
2. Implement request monitoring to identify and block patterns of enumerating `sourceID` values across different project paths.
3. Since no patch exists, restrict access to the Convoy management interface and API to trusted internal networks or authorized IP ranges.
4. Rotate any credentials currently stored in Convoy Source configurations if the instance is exposed to untrusted users.
5. If possible, disable or remove untrusted projects from instances hosting sensitive production configurations until a vendor patch for CVE-2026-81505 is released.
