---
title: Argo Workflows ConfigMap Sync Service Missing Authorization Vulnerability
slug: 2024-05-argo-configmap-auth-bypass
description: The Sync Service's ConfigMap-backed provider in Argo Workflows performs zero authorization checks on all CRUD operations, allowing any authenticated user to create, read, update, and delete Kubernetes ConfigMaps containing synchronization limits, potentially leading to denial of service, workflow disruption, information disclosure, or arbitrary ConfigMap manipulation in Argo Workflows versions v4.0.0 to v4.0.4.
date: "2024-05-03T16:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - argo-workflows
  - kubernetes
  - configmap
  - authorization
  - vulnerability
vendors:
  - Argo
products:
  - argo-workflows/v4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-xchc-cqwg-g76q
rules:
  - title: Argo Workflows ConfigMap Sync Service Modification
    description: Detects unauthorized modifications to ConfigMaps via the Argo Workflows Sync Service endpoints, indicating potential exploitation of the authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Argo Workflows ConfigMap Sync Service Access with Fake Token
    description: Detects access to the Argo Workflows ConfigMap Sync Service endpoints using a 'fake-token' in the Authorization header, indicating potential unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Argo Workflows, a Kubernetes-native workflow engine, is vulnerable to an authorization bypass in its Sync Service's ConfigMap-backed provider. This vulnerability, present in versions 4.0.0 through 4.0.4, stems from a lack of authorization checks on CRUD operations performed on ConfigMaps. This means that any authenticated user, even with a fake Bearer token, can create, read, update, and delete Kubernetes ConfigMaps used for synchronization limits. This flaw allows attackers to potentially disrupt workflow execution, access sensitive configuration data, or even manipulate ConfigMaps in namespaces accessible to the server's service account. The vulnerability was reported on May 4, 2026, and poses a significant risk to Argo Workflows deployments.

## Attack Chain

1.  Attacker gains network access to the Argo Server.
2.  Attacker authenticates to the Argo Server using any valid or even a "fake" Bearer token (e.g., `fake-token`).
3.  Attacker crafts a POST request to the `/api/v1/sync/default` endpoint to create a new Sync Limit ConfigMap with specified parameters like namespace, ConfigMap name, key, and limit.
4.  The Argo Server's `configMapSyncProvider.createSyncLimit` function executes without performing any authorization checks.
5.  The function uses the Kubernetes client to create a ConfigMap in the specified namespace based on the attacker's input.
6.  Attacker can subsequently send GET, PUT, or DELETE requests to `/api/v1/sync/default/{key}` to read, update, or delete existing Sync Limit ConfigMaps without authorization.
7.  The Argo Server processes these requests, modifying the ConfigMaps accordingly, due to the missing `auth.CanI` checks.
8.  The attacker disrupts workflow execution, gains access to sensitive configuration data, or manipulates ConfigMaps, leading to denial of service or other malicious outcomes.

## Impact

Successful exploitation of this vulnerability allows an attacker with network access to the Argo Server and valid or fake authentication credentials to perform several malicious actions. They can cause a denial of service by setting sync limits to zero or a very low number, effectively blocking parallel workflow execution. Attackers can also disrupt running workflows by modifying existing sync limits. Furthermore, they can gain access to sensitive information by reading ConfigMap data or manipulate ConfigMaps in any namespace accessible to the server's service account. This could lead to complete compromise of the Argo Workflows environment.

## Recommendation

*   Upgrade to Argo Workflows version 4.0.5 or later to patch CVE-2026-42297 and mitigate the missing authorization checks.
*   Monitor access logs on the Argo Server for unexpected API calls to the `/api/v1/sync` endpoints, especially POST, PUT, and DELETE requests, which could indicate unauthorized ConfigMap manipulation. Use the rule `Argo Workflows ConfigMap Sync Service Modification` to detect unauthorized modifications.
*   Implement network segmentation and access controls to limit network access to the Argo Server, reducing the attack surface.
