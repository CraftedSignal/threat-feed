---
title: Missing Authentication Vulnerability in fuint API
slug: 2026-10-fuint-missing-auth
description: The fuint platform contains a missing authentication vulnerability in the /clientApi/order/detail endpoint, allowing unauthenticated attackers to retrieve sensitive customer order PII via enumeration.
date: "2026-10-13T18:38:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fuint:fuint:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sensitive-data-exposure
  - cve-2026-110128
vendors:
  - fuint
products:
  - fuint (<= 4c4bc8a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can enumerate sequential orderId values without an Access-Token to expose buyer names, national ID numbers, phone numbers, addresses, WeChat openIds and verification codes.
    confidence_band: high
cves:
  - id: CVE-2026-110128
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110128
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch fuint to a version post-dating commit 4c4bc8a
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions up to 4c4bc8a
  hunt_leads:
    - lead: Search logs for HTTP 200 responses to /clientApi/order/detail with missing auth headers
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers enumerate endpoints without an Access-Token
  mitigation_plan:
    - priority: immediate
      action: Enforce authentication requirement for /clientApi/order/detail
      owner: IT Operations
      addresses: CVE-2026-110128
      evidence: Source identifies missing authentication vulnerability
---

The fuint platform, specifically versions up to commit 4c4bc8a, contains a critical missing authentication vulnerability within its client API. This flaw allows unauthenticated remote attackers to bypass access controls by omitting the required Access-Token header when querying the /clientApi/order/detail endpoint. By systematically enumerating sequential orderId values, an attacker can extract sensitive customer data associated with orders. The exposed information includes personally identifiable information (PII) such as full names, national ID numbers, phone numbers, physical addresses, WeChat openIds, and authentication verification codes. Because the vulnerability relies on predictable, sequential identifiers, the impact is significant, as an attacker can automate the retrieval of records across the entire customer database without requiring prior authorization or specific target knowledge.

## Impact

The vulnerability results in a massive unauthorized disclosure of PII for the organization's user base. Successful exploitation leads to the breach of sensitive data, including national IDs and contact details, posing significant legal and regulatory risks. The exposure of WeChat openIds and verification codes further facilitates downstream account takeover or social engineering attacks against the platform's customers.

## Recommendation

Prioritize the immediate audit of all publicly accessible API endpoints within the fuint application to ensure proper authentication middleware enforcement.

* Update the fuint platform to a version released after commit 4c4bc8a that implements mandatory authentication for the /clientApi/order/detail endpoint.
* Monitor web server logs for a high volume of requests to the /clientApi/order/detail endpoint originating from a single IP address with empty or missing authorization tokens.
* Analyze access logs for anomalous, sequential orderId patterns, which are indicative of an automated enumeration attack targeting this vulnerability.
