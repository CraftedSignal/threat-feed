---
title: Multiple Vulnerabilities in LibreOffice
slug: 2026-10-libreoffice-vulnerabilities
description: LibreOffice is affected by multiple vulnerabilities that could allow a local attacker to execute arbitrary code, manipulate data, or disclose sensitive information.
date: "2026-10-06T18:44:03Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - The Document Foundation
products:
  - LibreOffice
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A local attacker can exploit multiple vulnerabilities in LibreOffice to execute arbitrary code.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3738
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update LibreOffice to the latest stable release.
      owner: IT Operations
      addresses: LibreOffice local code execution vulnerabilities
      evidence: Source document indicates multiple vulnerabilities require remediation.
---

The Document Foundation has disclosed multiple security vulnerabilities affecting LibreOffice. These flaws allow a local attacker to perform various malicious actions, including information disclosure, unauthorized data manipulation, and arbitrary code execution. These vulnerabilities typically require the attacker to convince a user to open a specially crafted file or interact with a malicious document. The impact is significant for environments where users frequently handle untrusted documents, as successful exploitation can lead to a full compromise of the user workstation context. Organizations should ensure that LibreOffice is updated to the latest available version provided by their distribution or vendor to mitigate these risks.
