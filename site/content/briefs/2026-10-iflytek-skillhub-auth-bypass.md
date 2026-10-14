---
title: Unauthorized Skill Deletion in iFlytek SkillHub
slug: 2026-10-iflytek-skillhub-auth-bypass
description: iFlytek SkillHub versions through 0.2.22 contain a missing authorization vulnerability in the skill deletion API, allowing authenticated users to delete any user's skill data.
date: "2026-10-14T04:37:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:iflytek:skillhub:*:*:*:*:*:*:*:*
vendors:
  - iFlytek
products:
  - SkillHub (<= 0.2.22)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Attackers can locate targets through the anonymous search endpoint and trigger deletion without ownership checks, purging all versions, files, reviews, ratings and metadata.
    confidence_band: high
cves:
  - id: CVE-2026-110211
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110211
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit web access logs for DELETE requests to /api/cli/v1/skills/ where the user identity does not match the resource owner
      owner: SOC
      due: 24h
      evidence: Source confirms missing authorization on this specific endpoint
  mitigation_plan:
    - priority: immediate
      action: Identify and patch iFlytek SkillHub instances to the latest secure version once released
      owner: IT Operations
      addresses: CVE-2026-110211
      evidence: Vulnerability exists in version 0.2.22 and earlier
---

iFlytek SkillHub versions through 0.2.22 are affected by a missing authorization vulnerability (CVE-2026-110211). The vulnerability exists within the DELETE endpoint at /api/cli/v1/skills/{namespace}/{slug}. Due to the absence of proper ownership checks, any authenticated user can successfully execute a DELETE request against skills they do not own. Upon exploitation, the application permanently purges all associated data, including multiple versions of the skill, uploaded files, user reviews, ratings, and internal metadata. This flaw is particularly dangerous in multi-tenant or collaborative environments where users might target rival developers or perform malicious mass-deletion campaigns to disrupt service availability and integrity. Because the target identifiers (namespace and slug) can be discovered via an anonymous search endpoint provided by the platform, the bar for exploitation is extremely low.

## Impact

Successful exploitation results in the complete and irreversible loss of data associated with a skill. This impacts users by erasing their contributions, damaging project visibility, and destroying historical metadata such as reviews and ratings. In professional settings, this could lead to significant loss of intellectual property and reputational damage. The vulnerability affects all deployments of iFlytek SkillHub up to and including version 0.2.22.

## Recommendation

Prioritized actions to mitigate the risk of CVE-2026-110211:

* Immediately restrict access to the /api/cli/v1/skills/ endpoint if not required for standard operations, or verify if an update from iFlytek is available.
* Audit web server access logs for anomalous patterns of DELETE requests directed at the /api/cli/v1/skills/ endpoint to identify potential abuse.
* If logs indicate unauthorized deletion, enforce strict API authentication and authorization controls that map the requesting user's identity to the resource owner before permitting state-changing operations.
