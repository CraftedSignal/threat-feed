---
brief_id: brief-2026-10-30-rancher-auth-bypass
event_id: brief-2026-10-30-rancher-auth-bypass
revision: 2
activity_at: "2026-11-02T17:55:48Z"
revision_history:
  - revision: 2
    at: "2026-11-02T17:55:48Z"
    checksum: sha256:45284ed755afd8d7a5cac97b8f6e8988beb4e8e5c1c88a9772fd0dab47912205
    summary: severity → critical; added CVE-2026-88811
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - qa_status
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-88811
title: SUSE Rancher Manager authorization bypass (CVE-2026-104623)
slug: 2026-10-rancher-auth-bypass
description: An authorization bypass vulnerability in SUSE Rancher Manager (CVE-2026-104623) allows authenticated users to spawn an unprivileged shell pod in the cattle-system namespace.
date: "2026-10-30T23:05:08Z"
lastmod: "2026-11-02T17:55:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability; requires patch deployment
cpes:
  - cpe:2.3:a:suse:rancher_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - webserver
  - cloud
  - privilege-escalation
  - kubernetes
  - rbac
  - credential-leak
  - cloud-security
vendors:
  - SUSE
products:
  - SUSE Rancher Manager (< 2.15.3)
  - Rancher Manager (2.15.0-2.15.3, 2.14.0-2.14.7, 2.13.0-2.13.11, 2.12.0-2.12.15, 2.11.0-2.11.19)
  - Rancher Manager (2.15.2)
  - Rancher Webhook (0.11.0-0.11.4, 0.12.0-0.12.1)
  - Rancher Manager (2.15.0-2.15.3)
  - Rancher Manager (2.14.0-2.14.7)
  - Rancher Manager (2.13.0-2.13.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The meta proxy endpoint (/meta/proxy) contains a flaw in its request validation logic, potentially allowing unauthorized Server-Side Request Forgery or proxy abuse.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A privilege escalation issue was discovered in Rancher Manager's role-based access control.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Missing filtering in the SUSE Rancher Manager meta proxy could cause passed in rancher credentials to be leaked to cloud providers.
    confidence_band: high
cves:
  - id: CVE-2026-104623
    cvss: 6.3
    kev_status: "false"
  - id: CVE-2026-88809
    cvss: 7.6
    kev_status: "false"
  - id: CVE-2026-88810
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-88811
    cvss: 9.1
    kev_status: "false"
references:
  - https://github.com/rancher/rancher/security/advisories/GHSA-8x6f-2v58-x6p7
  - https://sploitus.com/exploit?id=FE9C2F0B-BAA4-509A-8238-5BB7DF6270D8
  - https://sploitus.com/exploit?id=FE9C2F0B-BAA4-509A-8238-5BB7DF6270D8&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88809
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88810
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88811
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internet-facing and internal Rancher Manager instances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects multiple Rancher Manager release branches
    - action: Patch Rancher Manager and Webhook to the fixed release versions.
      owner: IT Operations
      due: 48h
      evidence: Affected versions identified in NVD advisory.
    - action: Patch SUSE Rancher Manager instances to fixed versions
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-88811
  hunt_leads:
    - lead: Identify unauthorized access attempts to the /meta/proxy endpoint
      technique_id: T1190
      data_needed:
        - Rancher Manager application logs
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability logs a rejection, yet proceeds to forward the request through the proxy transport.
    - lead: Identify GlobalRoleBinding objects with inheritedNamespacedRules permissions that deviate from expected baseline authorizations.
      technique_id: T1068
      data_needed:
        - Kubernetes RBAC audit logs
        - Rancher Manager GlobalRole object configurations
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The inheritedNamespacedRules field propagates permissions into named namespaces of every downstream cluster.
    - lead: Inspect egress traffic from Rancher Manager to cloud provider APIs for credential headers
      technique_id: T1552.001
      data_needed:
        - Proxy logs
        - Cloud provider audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Missing filtering in meta proxy leads to leaked credentials to cloud providers.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rancher Manager to patched versions once available
      owner: IT Operations
      addresses: CVE-2026-88809
      evidence: NVD disclosure identifying affected versions
    - priority: immediate
      action: Review and audit current GlobalRole and GlobalRoleBinding assignments for non-admin users.
      owner: SOC
      addresses: CVE-2026-88810
      evidence: The flaw allows a non-administrative user to be granted permissions in downstream clusters that exceed those they already hold.
    - priority: immediate
      action: Rotate credentials used by Rancher Manager to interact with cloud providers
      owner: IT Operations
      addresses: CVE-2026-88811
      evidence: Vulnerability leads to credential exposure
updates:
  - at: "2026-11-02T17:53:48Z"
    level: L2
    summary: added coverage for Rancher Manager (2.15.0-2.15.3, 2.14.0-2.14.7, 2.13.0-2.13.11, 2.12.0-2.12.15, 2.11.0-2.11.19)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-88809
  - at: "2026-11-02T17:55:08Z"
    level: L2
    summary: added coverage for Rancher Manager (2.15.2) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-88810
  - at: "2026-11-02T17:55:13Z"
    level: L3
    summary: severity → critical; added CVE-2026-88811
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-88811
---

CVE-2026-104623 is an authorization bypass vulnerability affecting the `local-cluster-shell` feature in SUSE Rancher Manager. Authenticated Rancher users, including those with minimal global roles and no cluster-level privileges, can bypass authorization checks by using non-standard URL request shapes. This allows the creation of an interactive shell pod (`dashboard-shell-*`) in the `cattle-system` namespace. The issue was addressed in version 2.15.3 by enforcing a `SubjectAccessReview` within the handler.
