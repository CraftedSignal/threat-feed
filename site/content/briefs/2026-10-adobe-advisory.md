---
brief_id: brief-2026-10-28-adobe-advisory
event_id: brief-2026-10-28-adobe-advisory
revision: 1
activity_at: "2026-10-28T23:59:46Z"
title: 'Adobe: Security updates for Substance 3D Painter, Creative Cloud, Campaign Classic, and Connect'
slug: 2026-10-adobe-advisory
description: The Canadian Centre for Cyber Security has released an advisory concerning multiple security vulnerabilities in various Adobe products, recommending that users and administrators apply available security updates.
date: "2026-10-28T23:59:46Z"
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
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability-management
  - software-update
vendors:
  - Adobe
products:
  - Substance 3D Painter (<= 12.1.5)
  - Creative Cloud Desktop Application (<= 6.10)
  - Adobe Campaign Classic (<= 7.4.4 build 9402)
  - Adobe Connect Android Mobile App (<= 4.4)
  - Adobe Connect Desktop App (<= 2026.8.51 Win, 2026.08.45 Mac Silicon, 2026.01.39 Mac Intel)
references:
  - https://cyber.gc.ca/en/alerts-advisories/adobe-security-advisory-av26-1092
  - https://www.adobe.com/trust/security/products/substance3d-painter/apsb26-178.html
  - https://www.adobe.com/trust/security/products/creative-cloud/apsb26-135.html
  - https://www.adobe.com/trust/security/products/campaign/apsb26-162.html
  - https://www.adobe.com/trust/security/products/connect/apsb26-182.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Apply security updates as detailed in Adobe bulletins APSB26-178, APSB26-135, APSB26-162, and APSB26-182
      owner: IT Operations
      addresses: Affected Adobe software product suite
      evidence: The Cyber Centre encourages users and administrators to review the provided web links and apply any necessary updates
---

The Canadian Centre for Cyber Security (CCCS) has issued advisory AV26-1092 following the release of security updates by Adobe. These updates address multiple vulnerabilities across the Substance 3D Painter, Creative Cloud Desktop Application, Adobe Campaign Classic, and Adobe Connect product lines. The specific technical details of these vulnerabilities remain documented within the vendor-provided security bulletins linked below.

## Recommendation

- Audit the environment to identify installations of the affected Adobe products.
- Review the specific security bulletins (APSB26-178, APSB26-135, APSB26-162, APSB26-182) for versioning requirements.
- Apply the latest security updates provided by Adobe for the identified product versions as a matter of priority to remediate known vulnerabilities.
