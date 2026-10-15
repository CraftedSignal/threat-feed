---
title: Multiple Vulnerabilities in J4Care dcm4chee-arc-light
slug: 2026-10-j4care-dcm4chee
description: Multiple critical vulnerabilities in J4Care dcm4chee-arc-light 5.35.1 enable remote, unauthenticated attackers to manipulate medical records, exfiltrate sensitive patient data, and induce denial-of-service conditions.
date: "2026-10-15T17:00:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - healthcare
  - medical-device
  - vulnerability
  - remote-execution
vendors:
  - J4Care
products:
  - dcm4chee-arc-light (5.35.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: A remote peer can use C-FIND and C-GET to enumerate and retrieve patient information and medical images.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Changing a location to TO_DELETE causes PurgeStorageScheduler to delete the referenced object from storage.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-02
  - https://www.cve.org/CVERecord?id=CVE-2026-97851
  - https://www.cve.org/CVERecord?id=CVE-2026-107621
  - https://www.cve.org/CVERecord?id=CVE-2026-105273
  - https://www.cve.org/CVERecord?id=CVE-2026-101021
  - https://www.cve.org/CVERecord?id=CVE-2026-105279
  - https://www.cve.org/CVERecord?id=CVE-2026-105667
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade J4Care dcm4chee-arc-light to version 5.35.2 or later.
      owner: IT Operations
      due: 48h
      evidence: J4Care recommends users implement release 5.35.2 or later.
  mitigation_plan:
    - priority: immediate
      action: Restrict DICOM association acceptance to authorized AE titles.
      owner: IT Operations
      addresses: CVE-2026-105279
      evidence: The archive accepts DICOM associations from an unregistered calling AE.
---

J4Care dcm4chee-arc-light version 5.35.1 contains multiple critical vulnerabilities affecting the Healthcare and Public Health sector. These vulnerabilities, identified as CVE-2026-97851, CVE-2026-107621, CVE-2026-105273, CVE-2026-101021, CVE-2026-105279, and CVE-2026-105667, allow remote, unauthenticated attackers to exploit flaws in REST services and DICOM protocol handlers. The impact of these vulnerabilities is significant, enabling unauthorized modification or deletion of medical images, disclosure of sensitive patient records, injection of forged studies, and disruption of critical imaging services. Organizations utilizing this archiving solution should prioritize upgrading to version 5.35.2 or later to mitigate these risks.

## Attack Chain

1. Attacker performs network reconnaissance to identify J4Care dcm4chee-arc-light instances accessible via DICOM or REST ports.
2. Attacker initiates an unauthenticated DICOM association with the archive, leveraging the default configuration that accepts unregistered Application Entities (AEs).
3. Attacker uses the C-FIND and C-GET protocol commands to enumerate patient identifiers and retrieve images.
4. Attacker utilizes the C-STORE command to inject fabricated medical studies into the database under existing patient identities.
5. Attacker leverages the storage status-change REST service to alter location records for targeted DICOM instances.
6. PurgeStorageScheduler automatically deletes the referenced files from back-end storage based on the manipulated state.
7. Attacker sends specially crafted JPEG or MP4 files to trigger infinite loops during parsing, resulting in service denial.

## Impact

Successful exploitation risks the integrity and availability of medical imaging systems. Attackers can delete stored medical images, disclose confidential patient health information (PHI), corrupt patient record associations, and crash the archiving service. This poses immediate risks to patient care, operational continuity, and regulatory compliance within healthcare environments.

## Recommendation

* Patch affected systems by upgrading J4Care dcm4chee-arc-light to version 5.35.2 or later.
* Implement strict access control lists on DICOM and REST service ports to prevent unauthorized associations from unregistered Application Entities.
* Review logs for unusual C-FIND, C-GET, or C-STORE requests originating from unknown or unauthorized AE titles.
* Restrict network exposure of the dcm4chee-arc-light management interface to trusted administrative subnets.
