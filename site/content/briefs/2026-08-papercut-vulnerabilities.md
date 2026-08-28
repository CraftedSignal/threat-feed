---
title: Active Exploitation of PaperCut MF and NG
slug: 2026-08-papercut-vulnerabilities
description: PaperCut MF and NG are impacted by two actively exploited vulnerabilities, CVE-2026-82078 and CVE-2026-81578, which allow unauthenticated remote attackers to achieve arbitrary code execution and full system control.
date: "2026-08-28T14:28:32Z"
lastmod: "2026-08-28T15:10:17Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - PaperCut
products:
  - PaperCut MF
  - PaperCut NG
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Kwaadwillenden kunnen zonder inloggegevens via het netwerk misbruik maken van de kwetsbaarheden om de PaperCut-omgeving over te nemen.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: en zelf code uit te voeren.
    confidence_band: high
cves:
  - id: CVE-2026-81578
  - id: CVE-2026-82078
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-papercut-mf-en-ng-met-actief-misbruik-update-onmiddellijk
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1095/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch PaperCut MF and NG instances to remediate CVE-2026-82078 and CVE-2026-81578
      owner: IT Operations
      due: 24h
      evidence: NCSC-NL alert advises immediate updates to address active exploitation.
  hunt_leads:
    - lead: Anomalous process creation or unexpected network traffic originating from the PaperCut server
      technique_id: T1203
      data_needed:
        - Process creation logs (Event ID 1)
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NCSC recommends checking environment for signs of attack as per PaperCut bulletin.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches
      owner: IT Operations
      addresses: CVE-2026-82078, CVE-2026-81578
      evidence: NCSC-NL advisory recommends immediate installation of updates.
updates:
  - at: "2026-08-28T15:10:17Z"
    level: L2
    summary: added CVE-2026-81578 +1
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1095/
---

The Netherlands National Cyber Security Centre (NCSC-NL) has issued an urgent alert regarding the active exploitation of two critical vulnerabilities within PaperCut MF and PaperCut NG print management software. Identified as CVE-2026-82078 and CVE-2026-81578, these flaws enable unauthenticated remote attackers to compromise the print management environment. By bypassing authentication mechanisms, adversaries can gain full control over the application, leading to arbitrary code execution. This level of access provides a significant foothold within an organization's network, increasing the risk of lateral movement, data theft, and operational disruption. Given that exploitation is currently observed in the wild, the NCSC strongly advises organizations to verify their version status against the vendor's security bulletin and apply the provided patches immediately.

## Impact

Successful exploitation of these vulnerabilities allows attackers to seize control of the PaperCut environment without valid credentials. This results in the potential for complete system compromise, enabling further unauthorized access to sensitive internal systems and data. The risk of lateral movement from the compromised print server to other network segments represents a high-impact threat to organizational security and business continuity.

## Recommendation

- Identify all instances of PaperCut MF and PaperCut NG within the network and verify if they are running vulnerable versions.
- Apply the vendor-provided security updates for CVE-2026-82078 and CVE-2026-81578 as a matter of urgency.
- Perform log analysis on the PaperCut server for anomalous activity, such as unexpected process spawning or unauthorized access attempts, as documented in the official PaperCut security bulletin.
- If the environment status is unknown, contact IT service providers immediately to facilitate an audit and patching effort.
