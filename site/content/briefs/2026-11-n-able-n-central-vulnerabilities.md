---
brief_id: brief-2026-11-10-n-able-n-central-vulnerabilities
event_id: brief-2026-11-10-n-able-n-central-vulnerabilities
revision: 3
activity_at: "2026-11-10T16:27:14Z"
revision_history:
  - revision: 2
    at: "2026-11-10T10:32:18Z"
    checksum: sha256:928f77b7725ff061c08b8b7795620eb9194709813bc0a92921f1990af09d6941
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.securityweek.com/n-able-takes-n-central-offline-as-researcher-drops-over-30-zero-days/
  - revision: 3
    at: "2026-11-10T16:27:14Z"
    checksum: sha256:b095e544fbe7f09cbb2bdc387111a5abf1ea5d28a3e65aecf765e956ce3d4011
    summary: exploited:true; poc_available
    changed_fields:
      - exploitation_evidence
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.sophos.com/en-us/blog/n-able-issues-advisory-on-critical-vulnerabilities
title: 'N-able N-central: Multiple zero-day vulnerabilities (Able2Shell)'
slug: 2026-11-n-able-n-central-vulnerabilities
description: Security researcher Sean Bales disclosed 33 zero-day vulnerabilities, collectively known as Able2Shell, affecting N-able N-central and enabling remote code execution, credential theft, and unauthorized administrative access.
date: "2026-11-10T07:35:12Z"
lastmod: "2026-11-10T16:25:36Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.sophos.com/en-us/blog/n-able-issues-advisory-on-critical-vulnerabilities
  observed_at: "2026-11-10T00:00:00Z"
  confidence: medium
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
has_poc: true
tags:
  - vulnerability
  - zero-day
  - rce
  - n-able
vendors:
  - N-able
products:
  - N-central (2026.4.0.31)
  - N-central
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of these flaws can allow rogue administrative access to the N-central management interface.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Successful exploitation of these flaws can allow... command execution as root.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The identified zero-day vulnerabilities include credential disclosure.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/n-able-takes-hosted-n-central-offline.html
  - https://www.securityweek.com/n-able-takes-n-central-offline-as-researcher-drops-over-30-zero-days/
  - https://www.sophos.com/en-us/blog/n-able-issues-advisory-on-critical-vulnerabilities
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Shut down on-premises N-central servers until official patches are released.
      owner: IT Operations
      due: Immediate
      evidence: N-able is urging on-premises customers to shut down their servers until further notice.
  hunt_leads:
    - lead: Search for unexpected creation of administrative accounts or unusual login events in N-central management logs.
      technique_id: T1078
      data_needed:
        - N-central application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Multiple N-central zero-days enable anonymous credential theft, administrator creation.
  mitigation_plan:
    - priority: immediate
      action: Apply upcoming N-able hotfix to all N-central instances.
      owner: IT Operations
      addresses: Able2Shell zero-days
      evidence: The company also said... it is currently working on a hot fix to address them.
updates:
  - at: "2026-11-10T10:31:38Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/n-able-takes-n-central-offline-as-researcher-drops-over-30-zero-days/
  - at: "2026-11-10T16:25:36Z"
    level: L3
    summary: exploited:true; poc_available
    sources:
      - sophos-xops
    source_urls:
      - https://www.sophos.com/en-us/blog/n-able-issues-advisory-on-critical-vulnerabilities
---

N-able has taken its hosted N-central environment offline and advised on-premises customers to shut down their servers following the public disclosure of 33 zero-day vulnerabilities by researcher Sean Bales. These vulnerabilities, collectively referred to as Able2Shell, were tested against N-central Appliance version 2026.4.0.31. Affected environments include both hosted and on-premises deployments across the Americas, APAC, and Europe. N-able is currently developing hotfixes.

## Attack Chain
Documented exploit chains involve:
1. XXE / NCI trust abuse.
2. Support-token theft.
3. Unsigned NSP execution.
4. XSS-to-OGNL injection.
5. Authenticated reverse shells.

## Impact
Successful exploitation allows for anonymous credential theft, the creation of unauthorized administrator accounts, and remote code execution with root privileges. Additional impacts include arbitrary file writes, directory traversal, MDM impersonation, and audit tampering.

## Recommendation
- Shut down all on-premises N-central servers immediately per N-able's instructions.
- Monitor N-able official support channels for the release of hotfixes for version 2026.4.0.31 and apply them immediately upon availability.
- Audit N-central logs for unauthorized administrative account creation and unexpected reverse shell activity.
