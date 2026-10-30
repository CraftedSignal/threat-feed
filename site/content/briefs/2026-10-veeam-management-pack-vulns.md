---
brief_id: brief-2026-10-30-veeam-management-pack-vulns
event_id: brief-2026-10-30-veeam-management-pack-vulns
revision: 1
activity_at: "2026-10-30T21:19:54Z"
title: 'Veeam Management Pack: Remote code execution vulnerabilities'
slug: 2026-10-veeam-management-pack-vulns
description: Multiple vulnerabilities in Veeam Management Pack for Microsoft System Center allow remote attackers to achieve arbitrary code execution on affected systems.
date: "2026-10-30T21:19:54Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:veeam:management_pack_for_microsoft_system_center:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - enterprise-software
vendors:
  - Veeam
products:
  - Veeam Management Pack for Microsoft System Center (< 13.1.0.334)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: De multiples vulnérabilités ont été découvertes dans Veeam Management Pack. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance.
    confidence_band: high
cves:
  - id: CVE-2023-22793
    kev_status: unknown
  - id: CVE-2026-107238
    kev_status: unknown
  - id: CVE-2026-107239
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1426/
  - https://www.veeam.com/kb4961
  - https://www.cve.org/CVERecord?id=CVE-2023-22793
  - https://www.cve.org/CVERecord?id=CVE-2026-107238
  - https://www.cve.org/CVERecord?id=CVE-2026-107239
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Veeam Management Pack for Microsoft System Center to version 13.1 (build 13.1.0.334)
      owner: IT Operations
      due: 48h
      evidence: Veeam security bulletin kb4961
  hunt_leads:
    - lead: Identify child processes spawned by Veeam Management Pack services that deviate from baseline activity.
      technique_id: T1059
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerabilities allow for arbitrary code execution.
  mitigation_plan:
    - priority: immediate
      action: Apply security patch KB4961 to all Veeam Management Pack instances.
      owner: IT Operations
      addresses: CVE-2023-22793, CVE-2026-107238, CVE-2026-107239
      evidence: Veeam security bulletin kb4961
---

Multiple vulnerabilities have been identified in Veeam Management Pack for Microsoft System Center. These vulnerabilities allow a remote attacker to execute arbitrary code. The affected versions are all releases prior to 13.1 (build 13.1.0.334). Organizations should refer to the vendor security bulletin KB4961 for patch guidance.

## Impact
Successful exploitation allows for remote arbitrary code execution, which may lead to full system compromise of the affected host.

## Recommendation
- Update Veeam Management Pack for Microsoft System Center to version 13.1 (build 13.1.0.334) or later immediately as per Veeam security bulletin KB4961.
- Review network access logs for unusual inbound activity targeting the Veeam Management Pack service.
- Monitor logs for unauthorized process execution spawned by service accounts associated with System Center or Veeam services.
