---
title: Fission StorageSvc Unauthenticated Archive CRUD Vulnerability
slug: 2026-05-fission-storagesvc-auth-bypass
description: The Fission `storagesvc` component exposes unauthenticated CRUD operations on the `/v1/archive` endpoint, allowing any workload within the same Kubernetes cluster to enumerate archive IDs, download archives, upload arbitrary content, and delete archives, leading to potential code and secret exposure and function disruption.
date: "2026-05-21T20:08:37Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - kubernetes
  - serverless
  - authentication-bypass
  - code-execution
vendors:
  - Fission
products:
  - Fission (<= 1.22.0)
  - fission/fission
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Remote Services Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-chf8-4hv6-8pg6
  - https://github.com/fission/fission/releases/tag/v1.23.0
rules:
  - title: Detect Unauthenticated Access to Fission StorageSvc Archive Endpoint
    description: Detects unauthenticated GET requests to the Fission StorageSvc archive endpoints (`/v1/archives`, `/v1/archive/{archiveID}`), indicating potential unauthorized access. This rule detects the enumeration or download of function deployment archives (CVE-2026-46612).
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Fission StorageSvc Archive Manipulation
    description: Detects unauthenticated POST or DELETE requests to the Fission StorageSvc `/v1/archive` endpoint, indicating potential manipulation of function deployment archives (CVE-2026-46612).
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

Fission is a serverless framework for Kubernetes. A critical vulnerability exists within the `storagesvc` component of Fission versions 1.22.0 and earlier. The `storagesvc` registers archive CRUD handlers (`/v1/archive` GET / POST / DELETE and `/v1/archives` list) directly on its HTTP router without any authentication or authorization checks. This oversight enables any workload within the same Kubernetes cluster to interact with the archive storage service, bypassing tenant boundaries. The vulnerability was addressed in Fission v1.23.0 via PR #3368, which implemented HMAC verification, and defense in depth was added via PR #3365 which implemented a NetworkPolicy for the service. This unauthenticated access allows attackers to enumerate, download, modify, or delete function deployment archives, impacting code integrity and confidentiality.

## Attack Chain

1. An attacker compromises a pod within the Kubernetes cluster hosting Fission.
2. The compromised pod discovers the `storagesvc` ClusterIP.
3. The attacker sends an unauthenticated GET request to `/v1/archives` to enumerate archive IDs.
4. The attacker crafts a GET request to `/v1/archive/{archiveID}` to download a function's deployment archive, exposing source code and embedded secrets.
5. Alternatively, the attacker sends a DELETE request to `/v1/archive/{archiveID}` to remove a function archive, causing function specialization failures.
6. The attacker can also send a POST request to `/v1/archive` to upload a malicious archive.
7. Subsequent function specializations fetch and execute the uploaded malicious archive.
8. The attacker achieves arbitrary code execution within the Fission environment, potentially leading to further compromise.

## Impact

Successful exploitation allows a workload within the cluster to enumerate every function deployment archive, download sensitive function code and secrets, delete archives causing function failures, and upload malicious archives leading to code execution. This completely breaks tenant boundaries in multi-tenant Fission deployments. The absence of authentication on the `storagesvc` endpoint allows for trivial exploitation from any compromised workload within the cluster. This vulnerability is tracked as CVE-2026-46612.

## Recommendation

*   Upgrade Fission to v1.23.0 or later to incorporate the authentication fix introduced in PR #3368.
*   Enable the Helm chart's per-service NetworkPolicy (set `networkPolicy.enabled=true`) as outlined in the Mitigation section of the advisory.
*   Implement egress/ingress restrictions for `storagesvc` to limit network access to only the executor, builder, and fetcher pods, as described in the advisory.
*   Deploy the Sigma rule "Detect Unauthenticated Access to Fission StorageSvc Archive Endpoint" to detect unauthorized access attempts to the `/v1/archive` endpoint.
*   Deploy the Sigma rule "Detect Fission StorageSvc Archive Manipulation" to detect POST/DELETE attempts to the `/v1/archive` endpoint.
