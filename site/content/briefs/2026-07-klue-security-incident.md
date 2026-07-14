---
title: Klue Security Incident Leads to Recorded Future Salesforce Data Compromise
slug: 2026-07-klue-security-incident
description: A third-party marketing vendor, Klue, experienced unauthorized access to its integration layer, which connects to other SaaS platforms like Salesforce, leading to the compromise of an OAuth token and subsequent unauthorized access to Recorded Future's Salesforce account, where business data fields including customer contact names, email addresses, and potentially business contract information were accessed.
date: "2026-07-14T04:23:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - data-breach
  - supply-chain
  - cloud-security
  - saas-security
  - oauth
vendors:
  - Klue
  - Recorded Future
  - Salesforce
products:
  - Klue (Integration Layer)
  - Salesforce (Integration Feature)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Recorded FutureのSalesforceアカウントの一部が影響を受けたことを確認しました。
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: SalesforceとKlueとの間のあるインテグレーションに関連する侵害されたOAuthトークンを経由して、Recorded FutureのSalesforceアカウントの一部が影響を受けたことを確認しました。
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: 当該影響は当社のSalesforceデータベースに保存されているビジネスデータフィールド（顧客の連絡先名やメールアドレスなど）に限定されていると考えています。特定のビジネス契約情報も影響を受けたデータに含まれている可能性があります。
    confidence_band: high
references:
  - https://www.recordedfuture.com/blog/klue-security-incident-jp
---

On June 12, 2026, a third-party marketing vendor, Klue, experienced unauthorized access to its integration layer, which is designed to connect Klue with other marketing and sales SaaS platforms, including Salesforce. This incident led to the compromise of an OAuth token associated with the Klue-Salesforce integration, granting an unauthorized entity access to a portion of Recorded Future's Salesforce account. Recorded Future's CSIRT was notified on June 13, 2026, and their subsequent investigation revealed that specific business data fields, such as customer contact names, email addresses, and potentially business contract information, stored within their Salesforce database were accessed. Recorded Future concluded they were accidentally affected due to the compromised integration, not specifically targeted, and confirmed no access or compromise of their core systems, internal databases, or customer platform data.

## Attack Chain

1. An unauthorized entity gains initial access to Klue's integration layer, which facilitates connections between Klue and other SaaS platforms.
2. The unauthorized entity compromises an OAuth token used to establish and maintain the integration between Klue and Salesforce.
3. The compromised OAuth token is subsequently leveraged to gain unauthorized access to a specific portion of Recorded Future's Salesforce account.
4. Attackers navigate and access business data fields stored within the Salesforce database.
5. Specific customer contact names and email addresses are identified and accessed.
6. Potentially, business contract information stored in the Salesforce account is also accessed by the attackers.
7. The accessed sensitive customer and business data is likely exfiltrated from the Salesforce environment.

## Impact

The security incident resulted in the unauthorized access to and potential exfiltration of sensitive business data from Recorded Future's Salesforce account. This data included customer contact names, email addresses, and potentially specific business contract information. While Recorded Future's core platforms, intelligence graph, and other internal infrastructure were not affected, the incident exposed a subset of their customer's contact information. This type of data exposure can lead to increased risks of targeted phishing campaigns, business email compromise (BEC) attacks, and other forms of social engineering against the affected individuals and organizations.

## Recommendation

* Implement robust logging and monitoring for Salesforce activities to detect unauthorized access attempts or unusual data access patterns, given the compromise of a Salesforce account in this incident.
* Regularly audit and revoke OAuth tokens granted to third-party applications connecting to critical SaaS platforms like Salesforce, as a compromised OAuth token was the vector for unauthorized access in this event.
* Review third-party application integrations with Salesforce and other critical SaaS platforms to minimize the attack surface, considering Klue's role as a compromised third-party vendor in this incident.
