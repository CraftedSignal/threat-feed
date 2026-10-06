---
title: Prototype Pollution in @graphql-tools/utils
slug: 2026-10-graphql-tools-prototype-pollution
description: An unauthenticated remote denial-of-service vulnerability in @graphql-tools/utils allows attackers to crash node processes via prototype pollution in the mergeDeep utility function.
date: "2026-10-06T00:46:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:the-guild:graphql-tools:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - javascript
  - graphql
vendors:
  - The Guild
products:
  - '@graphql-tools/utils (<= 12.0.0)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This is remotely triggerable by an unauthenticated client with a single query against any supergraph that merges an object from two subgraphs, which is the ordinary @shareable or entity case, so it is a denial of service rather than a theoretical hardening issue.
    confidence_band: high
cves:
  - id: CVE-2026-104852
references:
  - https://github.com/advisories/GHSA-7mx3-vvmw-hjmv
  - https://github.com/ardatan/graphql-tools/pull/8423
  - https://github.com/graphql-hive/gateway/pull/2600
action_plan:
  priority: immediate_escalation
  owners:
    - Engineering
    - SOC
  immediate_actions:
    - action: Upgrade @graphql-tools/utils to 12.0.1 or later
      owner: Engineering
      due: 24h
      evidence: 'Source provides PR #8423 as the fix'
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF or API gateway rules to sanitize incoming GraphQL queries for reserved property aliases
      owner: SOC
      addresses: CVE-2026-104852
      evidence: Vulnerability relies on aliasing fields to __proto__, constructor, or prototype
---

The package @graphql-tools/utils (versions 12.0.0 and earlier) contains a critical prototype pollution vulnerability in its `mergeDeep` utility function, tracked as CVE-2026-104852. This vulnerability is triggered when a supergraph gateway, utilizing this utility for result merging, processes a malicious GraphQL query containing aliased fields such as `__proto__`, `constructor`, or `prototype`. 

Because the `mergeDeep` function recursively traverses inherited properties, an attacker can coerce the merge logic to traverse into core JavaScript object prototypes. By supplying crafted subgraph responses, the attacker can overwrite critical built-in properties like `Function.prototype.call`. This action corrupts the Node.js process environment, resulting in a persistent denial-of-service condition that impacts all subsequent requests until the service is restarted. This is a highly accessible vector as it requires only a single unauthenticated query against any gateway performing standard subgraph object merging.

## Impact

The vulnerability results in a total denial-of-service for the affected GraphQL gateway. Because the exploitation modifies core language primitives in the Node.js process memory, the crash is process-wide and persistent. Successful exploitation halts the processing of all incoming traffic, affecting services that rely on federated GraphQL schemas, such as Hive Gateway.

## Recommendation

Prioritized actions for engineering and security teams:
- Upgrade @graphql-tools/utils to a version beyond 12.0.0 immediately to include the patch implemented in PR #8423.
- If using Hive Gateway, upgrade to the version incorporating the mitigation in PR #2600.
- Implement request validation to filter or block GraphQL queries containing aliases targeting reserved JavaScript object keys such as `__proto__`, `constructor`, or `prototype` in field selection sets.
