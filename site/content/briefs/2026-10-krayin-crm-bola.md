---
title: Broken Object Level Authorization in Krayin CRM
slug: 2026-10-krayin-crm-bola
description: Krayin CRM versions before 2.2.7 contain a broken object level authorization vulnerability in the EmailController, allowing authenticated users to manipulate or delete emails belonging to other users.
date: "2026-10-19T16:08:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:krayin:krayin_crm:*:*:*:*:*:*:*:*
vendors:
  - Krayin
products:
  - Krayin CRM (< 2.2.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Krayin CRM before 2.2.7 contains a broken object level authorization vulnerability in EmailController write actions.
    confidence_band: high
cves:
  - id: CVE-2026-112287
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112287
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Krayin CRM to version 2.2.7 or later.
      owner: IT Operations
      due: 48h
      evidence: Krayin CRM before 2.2.7 contains a broken object level authorization vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Krayin CRM to version 2.2.7.
      owner: IT Operations
      addresses: CVE-2026-112287
      evidence: Krayin CRM before 2.2.7 contains a broken object level authorization vulnerability.
---

Krayin CRM versions prior to 2.2.7 are affected by a Broken Object Level Authorization (BOLA) vulnerability located within the EmailController. This flaw allows an authenticated user, even one with restricted access scopes, to perform unauthorized actions on emails owned by other users. By supplying specific numeric identifiers to affected write-action endpoints, an attacker can modify, re-send, or delete sensitive email communications.

The vulnerability exposes the application to data disclosure and integrity loss, as attackers can gain access to email subjects, bodies, and associated lead or person data. The impacted endpoints include update, destroy, mass-update, and mass-destroy operations. Successful exploitation allows an attacker to re-send emails by toggling the is_draft status to 0, potentially leading to unauthorized communication or data exfiltration.

## Attack Chain

1. Attacker authenticates to the Krayin CRM instance with a low-privileged, restricted-scope account.
2. Attacker discovers the numeric IDs of target emails belonging to other users via legitimate application functions or enumeration.
3. Attacker crafts an HTTP POST request targeting the `EmailController` write action (e.g., `update` or `mass-update`).
4. Attacker inserts the victim's email numeric ID into the request parameters to bypass object-level authorization checks.
5. Application server receives the request and fails to validate that the authenticated user owns the object associated with the provided ID.
6. The `EmailController` processes the request, executing the requested action (edit, delete, or re-send) on the target email.
7. Attacker successfully modifies or destroys the target email, or forces a re-send by setting `is_draft=0`, resulting in unauthorized data disclosure or integrity compromise.

## Impact

The vulnerability impacts users of Krayin CRM versions prior to 2.2.7. If exploited, attackers can access, modify, or permanently delete email communication and associated PII linked to leads and persons within the CRM. This compromises the confidentiality and integrity of customer relationship management data, potentially leading to reputational damage or regulatory compliance issues for affected organizations.

## Recommendation

* Upgrade Krayin CRM to version 2.2.7 or later immediately to patch the BOLA vulnerability in the EmailController.
* Audit access logs for repetitive attempts to access or modify email resources via `update`, `destroy`, `mass-update`, or `mass-destroy` endpoints, specifically monitoring for requests involving unexpected numeric IDs.
* Review user permissions and scope restrictions to ensure that only authorized accounts have access to sensitive email management functions.
