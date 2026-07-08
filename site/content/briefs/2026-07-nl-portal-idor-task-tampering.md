---
title: NL Portal IDOR Vulnerability Allows Tampering and Data Leakage of Other Users' Tasks (CVE-2026-49464)
slug: 2026-07-nl-portal-idor-task-tampering
description: An Insecure Direct Object Reference (IDOR) vulnerability, CVE-2026-49464, in NL Portal's Taak V2 implementation (versions 1.5.0 through 3.0.0) allows authenticated attackers to mark other users' tasks as complete, overwrite submitted data, and leak personal information by exploiting an authorization bypass in the `submitTaakV2` GraphQL endpoint.
date: "2026-07-08T21:14:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - graphql
  - data-tampering
  - data-leakage
  - authentication-bypass
  - cve
vendors:
  - NL Portal
products:
  - 'NL Portal Taak (vulnerable: >= 1.5.0, <= 3.0.0)'
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Receive the full task back in the GraphQL response, including the form data that the legitimate owner had already entered. This leaks personal data belonging to the original user.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Mark someone else's task as completed. Overwrite the data submitted with that task — the `verzonden_data` — with arbitrary input of their choosing.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6h3c-r723-7fx3
  - CVE-2026-49464
---

A high-severity Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-49464, has been identified in the NL Portal's Taak V2 implementation, affecting versions from 1.5.0 up to and including 3.0.0. This flaw permits any authenticated portal user (`burger` OAuth token holder) to manipulate and access other users' open tasks without proper authorization. Attackers can leverage this by submitting a known task ID to the `submitTaakV2` GraphQL endpoint, which lacks adequate authorization checks. This enables malicious users to mark tasks as completed, overwrite the `verzonden_data` with arbitrary input, and illicitly retrieve the full task, including sensitive, previously entered `portaalformulier` data from the legitimate owner. The vulnerable code was introduced in commit `bb1c1ecf` (2024-06-04) and shipped with the 1.5.x release line.

## Attack Chain

1. An authenticated attacker obtains a valid `burger` OAuth token to access the NL Portal.
2. The attacker identifies a target user's specific task ID (UUID), possibly through enumeration, social engineering, or prior compromise.
3. The attacker crafts a malicious GraphQL mutation request targeting the `submitTaakV2` endpoint.
4. The request includes the victim's task ID and arbitrary data intended to overwrite the original `submission` (`verzonden_data`).
5. The NL Portal backend, specifically the `nl.nlportal.zgw.taak.service.TaakService.submitTaakV2` resolver, processes the request without verifying if the task belongs to the authenticated user.
6. The backend transitions the identified task to the `AFGEROND` (completed) state and overwrites the `record.data.portaalformulier.verzondenData` with the attacker's supplied input.
7. The attacker receives the GraphQL response, which includes the entire task object, inadvertently exposing the legitimate owner's previously entered form data (confidentiality impact).
8. The victim's task data is tampered with, its integrity is compromised, and their private information is leaked to the attacker.

## Impact

This vulnerability significantly impacts both the integrity and confidentiality of user data within the NL Portal. Attackers can unilaterally mark other users' tasks as complete, regardless of their actual status, disrupting legitimate workflows. More critically, they can overwrite the data submitted with these tasks, leading to data corruption and potentially severe consequences depending on the nature of the forms. Furthermore, the attacker gains unauthorized access to sensitive personal data that other users had previously entered into their forms, violating privacy and potentially leading to further exploitation or identity theft. All users of NL Portal Taak versions 1.5.0 through 3.0.0 are at risk.

## Recommendation

* Upgrade NL Portal Taak to version **3.0.1** or later to address **CVE-2026-49464**.
* As a temporary workaround, block the `submitTaakV2` GraphQL mutation at your API gateway as described in the brief.
* Alternatively, restrict access to the `/graphql` endpoint to trusted networks only until the upgrade for **CVE-2026-49464** can be applied.
