---
brief_id: brief-2026-11-05-kyverno-privesc
event_id: brief-2026-11-05-kyverno-privesc
revision: 2
activity_at: "2026-11-05T09:06:42Z"
revision_history:
  - revision: 2
    at: "2026-11-05T09:06:42Z"
    checksum: sha256:020d042c457031eb1f701cc3fd6083f853bc1793e3c6d54edb79caa60a9a3da6
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122302&utm_source=rss&utm_medium=rss
title: 'Kyverno: Privilege escalation via generate-rule admission validation (CVE-2026-122302)'
slug: 2026-11-kyverno-privesc
description: Kyverno versions before 1.19.2 are vulnerable to a privilege escalation where namespace admins can bypass RBAC by crafting Policy resources that trigger the controller to perform unauthorized cluster-wide operations.
date: "2026-11-05T04:26:43Z"
lastmod: "2026-11-05T09:06:05Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kyverno:kyverno:*:*:*:*:*:*:*:*
  - cpe:2.3:a:kyverno:kyverno:1.17.0:*:*:*:*:*:*:*
  - cpe:2.3:a:kyverno:kyverno:1.19.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-122302&utm_source=rss&utm_medium=rss
tags:
  - kubernetes
  - cve
  - privilege-escalation
  - cloud-security
  - denial-of-service
  - supply-chain
vendors:
  - Kyverno
products:
  - Kyverno (< 1.19.2)
  - Kyverno (1.17.0 - 1.19.1)
  - Kyverno (1.17.0 <= v < 1.19.2)
  - Kyverno (1.16.0 - 1.19.1)
  - Kyverno (>= 1.17.0, < 1.19.2)
  - Kyverno (1.19.1)
  - Kyverno (1.11.0 <= version < 1.19.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Kyverno before 1.19.2 contains a privilege escalation vulnerability that allows namespace admins to create resources beyond their RBAC because generate-rule admission checks verify the controller's permissions, not the author's.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: OS Exhaustion Flood
    evidence: Attackers can create a Policy with crafted match and exclude names evaluated by ValidateMatchExcludeConflict, pinning cores and causing cluster-wide webhook timeouts that block resource operations.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can push an OCI referrer manifest with a non-string type field to bypass image verification under failurePolicy Ignore or crash-loop the reports-controller.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers who control registry referrers or signatures can publish small gzip layers that decompress beyond maxPayloadSize, causing admission controller OOM kills and denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-122302
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-122303
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-122304
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-122311
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-122313
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-122306
    cvss: 7.7
    kev_status: "false"
  - id: CVE-2026-122307
    cvss: 7.7
    kev_status: "false"
  - id: CVE-2026-122312
    cvss: 7.7
    kev_status: "false"
  - id: CVE-2026-122315
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-122316
    cvss: 8.5
    kev_status: "false"
  - id: CVE-2026-122323
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-122308
    kev_status: unknown
  - id: CVE-2026-122319
    kev_status: unknown
  - id: CVE-2026-122320
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122302
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122303
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122304
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122311
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122313
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122306
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122307
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122308
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122312
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122315
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122316
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122319
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122320
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122323
  - https://sploitus.com/exploit?id=CVE-2026-122302&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
    - Security Engineering
  immediate_actions:
    - action: Upgrade Kyverno to 1.19.2 or later across all clusters.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects Kyverno versions before 1.19.2.
    - action: Upgrade Kyverno to version 1.19.2 or later
      owner: IT Operations
      due: 24h
      evidence: Kyverno from 1.17.0 before 1.19.2 contains an authorization bypass
    - action: Patch Kyverno to version 1.19.2 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-122304 mitigation
    - action: Upgrade Kyverno to 1.19.2 or later
      owner: IT Operations
      due: 24h
      evidence: Kyverno from 1.16.0 before 1.19.2 fails to validate path segments
    - action: Upgrade Kyverno to version 1.19.2
      owner: IT Operations
      due: 48h
      evidence: Kyverno from 1.19.1 before 1.19.2 contains a namespace isolation bypass
    - action: Upgrade Kyverno to version 1.19.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Kyverno before 1.19.2 contains an unchecked type assertion.
  hunt_leads:
    - lead: Identify Policy or ClusterPolicy objects created or modified by non-cluster-admin users that utilize generate rules.
      technique_id: T1068
      data_needed:
        - Kubernetes API server audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can create a namespaced Policy with generate rules targeting other namespaces or cluster-scoped kinds.
    - lead: Identify Kyverno policies utilizing mutate-existing with targetMatchConstraints
      technique_id: T1068
      data_needed:
        - kubectl get cpol -o yaml
        - kubectl get pol -A -o yaml
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can return a CEL map literal fabricating a target with an attacker-chosen metadata.namespace
    - lead: Identify namespaces with CleanupPolicy resources containing apiCall or globalReference fields
      technique_id: T1068
      data_needed:
        - Kubernetes API server audit logs
        - Kubernetes resource manifest dump
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can create a namespaced CleanupPolicy with apiCall or globalReference context entries
    - lead: Identify creation or modification of NamespacedValidatingPolicy resources containing ".." path segments
      technique_id: T1068
      data_needed:
        - Kubernetes audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tenants who can create a NamespacedValidatingPolicy can insert .. segments
    - lead: Monitor Kubernetes audit logs for high-frequency or anomalous updates to Kyverno Policy or ClusterPolicy objects by non-admin service accounts.
      technique_id: T1499.001
      data_needed:
        - Kubernetes API server audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can create a Policy with crafted match and exclude names
    - lead: Identify creation of PolicyExceptions resources containing negated matchConditions
      technique_id: T1068
      data_needed:
        - Kubernetes API Audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Users with namespaced create rights on PolicyExceptions can inject negated matchConditions
    - lead: Identify Kyverno policies containing APICall definitions with query parameters
      technique_id: T1068
      data_needed:
        - Kubernetes API / Kyverno policy CRD definitions
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Users can supply a URLPath like /api/v1/nodes?x=/namespaces/default/ that passes validation
    - lead: Monitor Kubernetes logs for repetitive crash-loop events involving the kyverno-reports-controller pod.
      technique_id: T1499
      data_needed:
        - Kubernetes container logs / events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can ... crash-loop the reports-controller.
    - lead: Identify NamespacedMutatingPolicy objects utilizing CEL expressions to target resources outside the local namespace.
      technique_id: T1068
      data_needed:
        - Kubernetes audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can create a NamespacedMutatingPolicy targeting Namespace objects or victim-namespace resources via CEL expressions.
    - lead: Identify repeated OOMKilled events for Kyverno pods
      technique_id: T1498
      data_needed:
        - Kubernetes pod lifecycle events (kubectl get events -n kyverno)
        - Pod status showing OOMKilled
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: causing admission controller OOM kills and denial of service
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Kyverno 1.19.2+.
      owner: IT Operations
      addresses: CVE-2026-122302
      evidence: NVD advisory
    - priority: immediate
      action: Upgrade to Kyverno 1.19.2
      owner: IT Operations
      addresses: CVE-2026-122303
      evidence: Fixed in 1.19.2
    - priority: immediate
      action: Upgrade to version 1.19.2
      owner: IT Operations
      addresses: CVE-2026-122312
      evidence: Kyverno from 1.19.1 before 1.19.2 contains a namespace isolation bypass
    - priority: immediate
      action: Upgrade Kyverno to 1.19.2 or later.
      owner: IT Operations
      addresses: CVE-2026-122315
      evidence: Kyverno before 1.19.2 contains an unchecked type assertion.
    - priority: immediate
      action: Upgrade to Kyverno 1.19.2.
      owner: IT Operations
      addresses: CVE-2026-122316
      evidence: Kyverno 1.19.2 release contains the fix for the missing authorization vulnerability.
    - priority: immediate
      action: Upgrade Kyverno to version 1.19.2 or later
      owner: IT Operations
      addresses: CVE-2026-122323
      evidence: Kyverno from 1.11.0 before 1.19.2 contains an unbounded decompression vulnerability
updates:
  - at: "2026-11-05T04:27:36Z"
    level: L2
    summary: added coverage for Kyverno (1.19.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122312
  - at: "2026-11-05T04:27:45Z"
    level: L2
    summary: added coverage for Kyverno (< 1.19.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122315
  - at: "2026-11-05T04:27:48Z"
    level: L2
    summary: added coverage for Kyverno (1.17.0 - 1.19.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122316
  - at: "2026-11-05T04:28:04Z"
    level: L2
    summary: added coverage for Kyverno (1.11.0 <= version < 1.19.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122323
  - at: "2026-11-05T09:06:05Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122302&utm_source=rss&utm_medium=rss
---

Kyverno versions prior to 1.19.2 contain a vulnerability where generate-rule admission checks incorrectly validate permissions against the controller's identity instead of the author's identity. A namespace administrator can create a malicious Policy resource containing generate rules that target other namespaces or cluster-scoped resources. The background controller, operating with higher privileges, executes these rules, effectively allowing the namespace admin to escalate privileges and create or clone resources across the cluster.

## Impact

Successful exploitation allows a user with restricted namespace-level permissions to perform operations outside their authorized scope, including modifying cluster-scoped resources or resources in other namespaces.

## Recommendation

- Upgrade Kyverno to version 1.19.2 or later immediately.
- Audit existing Kyverno ClusterPolicy and Policy resources for unexpected generate rules, particularly those targeting namespaces other than the one where the policy resides or cluster-scoped kinds.
- Implement Admission Control policies to restrict the ability of namespace-scoped users to create or modify Kyverno Policy objects if not explicitly required by business workflows.
