---
title: Denial of Service Vulnerability in Chroma 1.5.9 via HNSW Index Parameters
slug: 2026-09-chroma-dos
description: Chroma 1.5.9 is vulnerable to an unauthenticated denial-of-service attack due to insufficient bounds validation on HNSW index parameters during collection creation, allowing memory exhaustion.
date: "2026-09-04T19:26:39Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:trychroma:chroma:1.5.9:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - cve
vendors:
  - Chroma
products:
  - Chroma (1.5.9)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Unauthenticated attackers can supply arbitrarily large parameter values to exhaust server memory and cause denial of service during index compaction.
    confidence_band: high
cves:
  - id: CVE-2026-85664
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85664
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory all Chroma instances to identify version 1.5.9 deployments
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85664 affects Chroma 1.5.9
  mitigation_plan:
    - priority: immediate
      action: Apply patches provided by Chroma for CVE-2026-85664
      owner: IT Operations
      addresses: CVE-2026-85664
      evidence: Source documentation for CVE-2026-85664
---

Chroma version 1.5.9 contains a high-severity vulnerability (CVE-2026-85664) within its handling of Hierarchical Navigable Small World (HNSW) index parameters. The application fails to perform proper bounds validation on the 'max_neighbors', 'ef_construction', and 'ef_search' parameters when processing collection-create API requests. An unauthenticated attacker can exploit this flaw by sending crafted requests containing arbitrarily large integer values for these parameters. Upon processing, the server attempts to allocate excessive memory resources to support the requested index dimensions, leading to heap exhaustion and a denial-of-service condition during the subsequent index compaction phase. This vulnerability poses a significant risk to the stability of self-hosted Chroma instances, as it does not require prior authentication to trigger.

## Impact

Successful exploitation results in an immediate service denial for the target Chroma instance. By repeatedly sending these malformed requests, an attacker can prevent the service from recovering, effectively rendering the vector database unavailable for legitimate application traffic. The impact is primarily local availability, affecting any dependent AI or data pipeline relying on the Chroma instance for storage and retrieval operations.

## Recommendation

Prioritize the identification and patching of Chroma instances running version 1.5.9. As the vendor releases security updates or patches addressing CVE-2026-85664, apply them to all internet-facing and internal Chroma deployments immediately. Until a patch is available, implement network-level access control lists (ACLs) or API gateway request validation to filter requests targeting the collection-create endpoint, ensuring that the integer values for HNSW index parameters fall within reasonable, documented operational limits.
