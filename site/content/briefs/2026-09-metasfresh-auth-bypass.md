---
title: Authorization Bypass in metasfresh DocumentAttachmentsRestController and CommentsRestController
slug: 2026-09-metasfresh-auth-bypass
description: Authenticated attackers can exploit improper record-level authorization checks in metasfresh ERP to perform unauthorized read, write, and delete operations on attachments and comments.
date: "2026-09-16T21:53:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - authorization-bypass
  - erp
vendors:
  - metasfresh
products:
  - metasfresh ERP
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can enumerate sequential document identifiers to read, replace, and delete attachments and comments.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92752
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review access logs for high-frequency requests to REST controllers
      owner: SOC
      due: 24h
      evidence: NVD vulnerability disclosure regarding controller enumeration
  mitigation_plan:
    - priority: immediate
      action: Patch metasfresh ERP once the vendor releases a fixed version addressing CVE-2026-92752
      owner: IT Operations
      addresses: CVE-2026-92752
      evidence: NVD vulnerability entry
---

The metasfresh ERP platform contains a critical authorization flaw (CVE-2026-92752) affecting the DocumentAttachmentsRestController and CommentsRestController endpoints. The vulnerability stems from the application verifying only that a user is authenticated, while failing to validate record-level permissions for the requested resources. This oversight allows an authenticated user to perform unauthorized actions on data restricted to other roles. By enumerating sequential document or comment identifiers, an attacker can access, modify, or delete sensitive attachments and comments belonging to records they should not have visibility into. Given the sensitive nature of business documents and communication within an ERP system, this flaw poses a high risk to data confidentiality and integrity. The issue allows for mass enumeration and data manipulation, which could be leveraged to exfiltrate proprietary information or disrupt business workflows by deleting critical project comments and files.

## Impact

The vulnerability enables unauthorized access to sensitive business data within the metasfresh ERP environment. Impacted organizations face potential data breaches of customer information, project details, and financial documentation through the unauthorized exfiltration of attachments. Furthermore, the ability to replace or delete comments and attachments can result in data loss or the corruption of audit trails, impacting business continuity and compliance efforts.

## Recommendation

1. Monitor web server logs for suspicious enumeration patterns, such as a high volume of sequential requests to DocumentAttachmentsRestController or CommentsRestController endpoints from a single user session.
2. Implement strict access control lists at the application level to ensure that user sessions are validated against specific record IDs before granting read, write, or delete permissions.
3. Review audit logs for abnormal patterns of document deletion or modification originating from unauthorized user roles.
4. Ensure all instances of metasfresh ERP are updated to the latest version once a patch is provided by the vendor.
