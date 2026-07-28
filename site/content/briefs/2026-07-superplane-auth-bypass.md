---
title: SuperPlane Broken Object-Level Authorization Vulnerability (CVE-2026-57510)
slug: 2026-07-superplane-auth-bypass
description: A critical broken object-level authorization vulnerability in SuperPlane's CanvasService gRPC handlers, tracked as CVE-2026-57510, allows authenticated users with viewer-level access to bypass organization scoping and access resources across tenant boundaries, leading to data collection and system impact.
date: "2026-07-28T20:22:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - api-security
  - saas
  - cloud
  - multi-tenancy
  - grpc
  - cve
vendors:
  - SuperPlane
products:
  - SuperPlane < 0.27.0
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: read cross-tenant execution history and event payloads containing sensitive secrets
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: delete arbitrary canvases
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: disrupt automation workflows across tenant boundaries
    confidence_band: high
cves:
  - id: CVE-2026-57510
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57510
---

CVE-2026-57510 details a broken object-level authorization vulnerability affecting SuperPlane versions prior to 0.27.0. This flaw resides within the CanvasService gRPC handlers, which are responsible for managing canvas and queue resources. An authenticated user with legitimate viewer-level access to one organization can exploit this vulnerability to gain unauthorized access to resources belonging to other organizations. By supplying arbitrary canvas or queue Universally Unique Identifiers (UUIDs) without proper organization scoping, an attacker can bypass access controls. This allows for reading sensitive cross-tenant execution history and event payloads that may contain secrets, writing unauthorized queue items and canvas events into victim organizations, deleting arbitrary canvases, and ultimately disrupting critical automation workflows across different tenant environments. The vulnerability poses a significant risk to data confidentiality, integrity, and system availability in multi-tenant SuperPlane deployments.

## Attack Chain

1. An attacker gains legitimate authenticated viewer-level access to a SuperPlane organization.
2. The attacker identifies the target SuperPlane instance is running a version prior to 0.27.0.
3. The attacker crafts gRPC requests targeting the CanvasService handlers.
4. The attacker includes arbitrary canvas or queue UUIDs in these requests that do not belong to their authorized organization.
5. Due to the broken object-level authorization, the CanvasService gRPC handlers process these requests without enforcing organization-level scoping.
6. The attacker successfully accesses resources (e.g., execution history, event payloads) belonging to other organizations.
7. The attacker leverages this access to read sensitive secrets, write malicious queue items or canvas events, or delete critical canvases.
8. The attacker disrupts automation workflows across tenant boundaries, achieving data collection and system impact objectives.

## Impact

Successful exploitation of CVE-2026-57510 can lead to severe consequences for SuperPlane deployments utilizing versions prior to 0.27.0. Attackers can read sensitive cross-tenant execution history and event payloads, which may contain critical secrets, compromising data confidentiality across multiple organizations. Furthermore, the vulnerability enables unauthorized modification of data by allowing attackers to write queue items and canvas events into victim organizations. The ability to delete arbitrary canvases can result in significant data loss and disruption. Critically, this flaw can be leveraged to disrupt automation workflows across tenant boundaries, leading to service degradation, operational outages, and potentially widespread business impact for affected SuperPlane customers. The broad scope of potential impact makes this a high-severity threat.

## Recommendation

* Immediately upgrade all SuperPlane installations to version 0.27.0 or later to patch CVE-2026-57510.
* Implement robust monitoring for unusual gRPC activity within your SuperPlane environment, specifically looking for attempts to access or manipulate canvas or queue UUIDs that are not associated with the authenticated user's organization.
* Review access logs for any indications of cross-tenant resource access by single-tenant authenticated users, particularly after patching CVE-2026-57510.
