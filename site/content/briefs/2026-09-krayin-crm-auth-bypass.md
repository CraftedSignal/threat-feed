---
title: Authentication Bypass in Krayin CRM Inbound Parse Endpoint
slug: 2026-09-krayin-crm-auth-bypass
description: An authentication bypass vulnerability in Krayin CRM version 2.2.6 and earlier allows unauthenticated attackers to inject arbitrary, forged email messages into the CRM inbox via the /admin/mail/inbound-parse endpoint.
date: "2026-09-14T19:35:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:krayin:crm:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - crm
vendors:
  - Krayin
products:
  - Krayin CRM (<= 2.2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Krayin CRM through 2.2.6 exposes the POST /admin/mail/inbound-parse endpoint without authentication
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90944
rules:
  - title: Detects CVE-2026-90944 Exploitation - Unauthenticated Email Injection via /admin/mail/inbound-parse
    description: Detects unauthorized POST requests to the /admin/mail/inbound-parse endpoint which indicates potential exploitation of CVE-2026-90944.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify access to /admin/mail/inbound-parse
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-90944 vulnerability assessment
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /admin/mail/inbound-parse via network controls
      owner: IT Operations
      addresses: CVE-2026-90944
      evidence: Source advisory
---

Krayin CRM versions through 2.2.6 contain a critical authentication bypass vulnerability identified as CVE-2026-90944. The vulnerability exists within the /admin/mail/inbound-parse endpoint, which fails to enforce authentication checks. This oversight allows remote, unauthenticated attackers to send crafted HTTP POST requests containing arbitrary RFC 2822 formatted messages. By manipulating these requests, an attacker can forge sender information, headers, subjects, and email bodies. Crucially, these messages can be injected directly into existing conversation threads within the CRM, potentially facilitating social engineering, credential harvesting, or internal misinformation campaigns by appearing as legitimate customer or internal communications. This vulnerability poses a significant risk to the integrity of business communications processed through the CRM platform.

## Impact

Successful exploitation allows for the injection of arbitrary email content into the CRM system. This can be weaponized to conduct sophisticated social engineering attacks by inserting forged replies into active customer support or sales threads. Organizations relying on Krayin CRM to manage high-trust communications are at risk of data integrity compromise and potential financial or reputational damage if attackers successfully impersonate clients or internal staff.

## Recommendation

* Immediately restrict network access to the /admin/mail/inbound-parse endpoint at the web server or firewall level to trusted IP ranges only.
* Audit existing CRM threads for any anomalous or unexpected email entries that may have been injected via this vulnerability.
* Monitor web server access logs for unauthorized POST requests directed to the /admin/mail/inbound-parse endpoint.
* Verify internal Krayin CRM versioning and ensure all instances are upgraded to a version that patches CVE-2026-90944 as soon as the vendor makes such a release available.
