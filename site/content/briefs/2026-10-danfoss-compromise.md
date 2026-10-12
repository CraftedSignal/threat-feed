---
title: Security Incidents Targeting Danfoss AK-SM and AK-SC Series Controllers
slug: 2026-10-danfoss-compromise
description: CERT-FR reports widespread compromises of Danfoss AK-SM and AK-SC series controllers resulting from the exposure of management interfaces directly to the internet.
date: "2026-10-12T18:29:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - ot
  - vulnerability
  - exposure
vendors:
  - Danfoss
products:
  - AK-SM series
  - AK-SC series
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: L'exposition d'une interface de gestion sur Internet est contraire aux bonnes pratiques.
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-012/
  - https://www.cert.ssi.gouv.fr/dur/CERTFR-2025-DUR-003/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - OT Security
  immediate_actions:
    - action: Audit network perimeter for exposed management interfaces of Danfoss AK-SM and AK-SC controllers.
      owner: SOC
      due: 24h
      evidence: Source explicitly advises disconnecting or filtering access to these instances.
  mitigation_plan:
    - priority: immediate
      action: Remove direct internet access; implement IP whitelisting for management ports.
      owner: IT Operations
      addresses: Exposed controller management interfaces
      evidence: CERT-FR recommended actions.
---

The French National Cybersecurity Agency (ANSSI) has issued an alert regarding numerous observed compromises of Danfoss AK-SM and AK-SC series controllers. The primary vector for these incidents is the exposure of device management interfaces directly to the public internet, which facilitates unauthorized access. These devices, commonly used in industrial or facility management, are highly vulnerable when reachable without proper perimeter protection. Defenders are urged to immediately audit internet-facing exposures of these controllers. In cases where remote administration is strictly required, ANSSI recommends strictly restricting access to a list of trusted IP addresses via network access control lists (ACLs).

## Impact

Successful exploitation results in full compromise of the affected controllers. Given the nature of these devices, which are typically used for industrial control and monitoring, a compromise may lead to loss of availability, unauthorized manipulation of the controlled environment, or lateral movement into broader operational technology networks.

## Recommendation

* Immediately disconnect all Danfoss AK-SM and AK-SC series controllers from the public internet.
* Implement strict network-level filtering to allow access only from authorized and trusted management IP addresses.
* If compromise is suspected, conduct a full factory reset (Factory Reset) and reconfigure the equipment globally.
* Perform a mandatory rotation of all system credentials and audit user accounts for unauthorized modifications.
* Apply all available security patches provided by the vendor to remediate known vulnerabilities.
