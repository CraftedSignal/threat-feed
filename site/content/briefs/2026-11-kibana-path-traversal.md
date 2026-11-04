---
brief_id: brief-2026-11-03-kibana-path-traversal
event_id: brief-2026-11-03-kibana-path-traversal
revision: 2
activity_at: "2026-11-04T16:18:46Z"
revision_history:
  - revision: 2
    at: "2026-11-04T16:18:46Z"
    checksum: sha256:3264ccb9ca361a0c06ddbffe482434cd3c13cb1b8a9f1f209f3168f95466a9e9
    summary: added coverage for Kibana
    changed_fields:
      - action_plan
      - lastmod
      - priority_signals
      - references
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4336
title: 'Elastic Kibana: Path traversal in Fleet feature (CVE-2026-115294)'
slug: 2026-11-kibana-path-traversal
description: CVE-2026-115294 is a path traversal vulnerability in the Kibana Fleet feature that allows low-privileged users with agent policy write access to manipulate administrative actions, resulting in unauthorized resource deletion.
date: "2026-11-03T18:05:23Z"
lastmod: "2026-11-04T16:16:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of Fleet access logs.
cpes:
  - cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - cve-2026-115294
  - elastic-kibana
  - vulnerability
  - web-application
  - security-advisory
vendors:
  - Elastic
products:
  - Kibana
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low-privileged user with Fleet agent policies write access could cause a subsequent administrative action to act on unintended resources.
    confidence_band: high
cves:
  - id: CVE-2026-115294
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115294
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4336
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict Fleet agent policy write access to high-privileged administrative accounts.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability scope is specific to users with Fleet agent policies write access.
    - action: Perform an inventory of all Kibana versions in the environment.
      owner: IT Operations
      due: 24h
      evidence: BSI advisory warrants identification of affected assets.
  enrichment_needed:
    - item: CVE identifiers and patched versions
      owner: CTI
      reason: Necessary to determine the urgency and specific remediation path.
      evidence: Source lacks technical specifics.
  hunt_leads:
    - lead: Monitor Kibana audit logs for delete actions performed on spaces or assets by low-privileged user accounts.
      technique_id: T1068
      data_needed:
        - Kibana audit/access logs
        - Fleet API activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation results in unauthorized deletion of Kibana spaces and organizational assets.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-115294 immediately upon release by Elastic.
      owner: IT Operations
      addresses: CVE-2026-115294
      evidence: Vendor security advisory recommendation.
    - priority: immediate
      action: Apply future security updates provided by Elastic for Kibana once released.
      owner: IT Operations
      addresses: Multiple reported vulnerabilities
      evidence: Standard remediation for software-specific security vulnerabilities.
  gaps:
    - Missing version-specific scope for remediation.
updates:
  - at: "2026-11-04T16:16:48Z"
    level: L1
    summary: added coverage for Kibana
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4336
---

A path traversal vulnerability exists in the Kibana Fleet feature, tracked as CVE-2026-115294. A user with low-privileged access to modify Fleet agent policies can manipulate resource paths. When an administrator subsequently interacts with the affected Fleet interface, these manipulated paths can result in the deletion of unauthorized resources, such as Kibana spaces and other organizational assets.

## Impact

Successful exploitation allows low-privileged users to bypass access controls and trigger the unauthorized deletion of resources they are not otherwise authorized to modify or delete.

## Recommendation

1. Inventory all instances of Kibana where the Fleet feature is enabled.
2. Review and restrict access to Fleet agent policy management to only essential administrative roles until a security update is applied.
3. Monitor administrative logs for unexpected deletion of Kibana spaces or management assets initiated by low-privileged user contexts.
4. Apply the forthcoming patch from Elastic once released to address the path traversal (CWE-22) in the Fleet feature.
