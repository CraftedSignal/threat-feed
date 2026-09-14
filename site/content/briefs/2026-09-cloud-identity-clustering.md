---
title: Detecting Identity Masquerading via Behavioral Clustering
slug: 2026-09-cloud-identity-clustering
description: Security researchers have developed a behavioral clustering model using unsupervised machine learning to differentiate between legitimate cloud functional roles and attackers masquerading as authorized identities.
date: "2026-09-14T12:57:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - identity-access-management
  - behavior-analysis
  - detection-engineering
vendors:
  - Amazon
products:
  - AWS Identity and Access Management
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036.005
    technique_name: 'Masquerading: Match Legitimate Name or Location'
    evidence: Attackers routinely use masquerading techniques like pre-existing permission profiles and benign labels to make malicious activity harder to detect.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/behavioral-clustering-map-to-cloud-identities/
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security Team
  immediate_actions:
    - action: Audit cloud identity behavioral baselines to identify identities with excessive scope or anomalous API usage.
      owner: Cloud Security Team
      due: 7d
      evidence: Research suggests mapping identity roles to distinguish between administration and backup/dev roles.
  hunt_leads:
    - lead: Identify identities that perform cross-account role modifications or resource discovery outside of defined DevOps or admin clusters.
      technique_id: T1098.003
      data_needed:
        - AWS CloudTrail Event History
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Cortex alerts provided in the report demonstrate that these actions are key indicators of account manipulation.
---

Researchers at Unit 42 have identified that attackers frequently bypass traditional identity and access management (IAM) controls by using masquerading techniques. By leveraging pre-existing permission profiles, benign labels, and legitimate service accounts, adversaries obscure their actions within cloud environments. The research analyzed behavior from over 40,000 identities across 125 cloud environments, establishing that cloud identities naturally aggregate into distinct functional clusters based on their API invocation patterns. 

Defenders can move beyond static policy reviews, which often fail to account for over-privileged identities, by implementing behavioral clustering using algorithms like UMAP and HDBSCAN. By mapping observed activity against these clusters, organizations can identify anomalies where an identity deviates from its typical functional role (e.g., an administrator account performing discovery activity inconsistent with console user patterns). This approach provides context for cloud detection and response (CDR) efforts, allowing for the classification of identities at scale using lightweight SQL heuristics derived from these clusters.

## Impact

The use of masquerading techniques allows attackers to conduct reconnaissance, account manipulation, and data exfiltration while blending into standard administrative or service-level traffic. If undetected, this leads to unauthorized resource discovery, permission modifications, and the compromise of cloud-native infrastructure, with the potential for widespread data loss or persistent unauthorized access across multiple cloud projects.

## Recommendation

- Implement behavioral profiling to categorize service accounts and human identities based on observed API activity rather than solely relying on assigned IAM policies.
- Integrate cloud detection and response (CDR) capabilities to monitor for deviations from baseline functional behavior, specifically focusing on cross-account permission modifications and unauthorized resource discovery.
- Deploy SQL-based heuristic logic to track identities identified as administrators or DevOps roles and alert on high-risk operations such as `DeleteBucket` or `ModifyRolePolicy` when originating from unusual behavioral clusters.
- Review the list of Cortex XDR/XSIAM alerts identified in the research to prioritize the enablement of telemetry covering cloud administration commands (T1651) and account manipulation (T1098.003).
