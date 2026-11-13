---
brief_id: brief-2026-11-13-ultravnc-dos
event_id: brief-2026-11-13-ultravnc-dos
revision: 1
activity_at: "2026-11-13T16:07:31Z"
title: 'UltraVNC: Remote denial of service and potential arbitrary code execution'
slug: 2026-11-ultravnc-dos
description: A vulnerability in UltraVNC allows a remote, unauthenticated attacker to trigger a denial of service condition or potentially execute arbitrary code.
date: "2026-11-13T16:07:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
vendors:
  - UltraVNC
products:
  - UltraVNC
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in UltraVNC ausnutzen, um einen Denial-of-Service-Angriff durchzuführen oder beliebigen Programmcode auszuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4566
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems running UltraVNC to assess exposure.
      owner: IT Operations
      due: 48h
      evidence: Advisory identifies vulnerability in UltraVNC.
  hunt_leads:
    - lead: Monitor firewall logs for unusual or high-frequency traffic directed at UltraVNC listening ports, typically port 5900, from unauthorized external IP addresses.
      technique_id: T1499
      data_needed:
        - Firewall logs
        - Network traffic logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is described as allowing a remote, anonymous attacker to trigger a denial of service.
---

According to the BSI security advisory, a vulnerability in UltraVNC permits a remote, unauthenticated attacker to cause a denial-of-service condition. The advisory notes that the same vulnerability may also allow for arbitrary code execution. Details regarding the specific vulnerability class or technical root cause have not been disclosed by the vendor.

## Impact

Successful exploitation may lead to a denial-of-service (system unavailability) or potential arbitrary code execution on systems running vulnerable versions of UltraVNC.

## Recommendation

Inventory systems currently running UltraVNC software. Monitor official vendor channels for the release of security updates addressing this vulnerability and prepare to patch systems immediately once a fix is available.
