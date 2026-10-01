---
title: Filter Injection Vulnerability in n8n Supabase Node
slug: 2026-10-n8n-supabase-injection
description: A filter injection vulnerability in the n8n Supabase node (CVE-2026-103248) allows attackers to perform unauthorized data exfiltration, modification, or deletion by injecting malicious filter expressions.
date: "2026-10-01T12:41:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:n8n:n8n:*:*:*:*:*:*:*:*
tags:
  - injection
  - vulnerability
  - n8n
  - database
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.80, 2.0.0-2.39.5, 2.40.0)
cves:
  - id: CVE-2026-103248
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103248
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade n8n software to versions 1.123.80, 2.39.6, or 2.40.1.
      owner: IT Operations
      due: 48h
      evidence: Vendor patch recommendation for CVE-2026-103248.
  mitigation_plan:
    - priority: immediate
      action: Upgrade n8n software to 1.123.80, 2.39.6, 2.40.1 or later.
      owner: IT Operations
      addresses: CVE-2026-103248
      evidence: NVD vulnerability details.
---

n8n versions before 1.123.80, from 2.0.0 before 2.39.6, and from 2.40.0 before 2.40.1 contain a filter injection vulnerability within the Supabase node when operating in 'Filters (String)' mode. The vulnerability stems from the application's failure to properly escape or sanitize field values before constructing database queries. This flaw enables unauthenticated attackers to manipulate query logic by injecting arbitrary filter expressions. If successfully exploited, an attacker can bypass intended access controls to read, update, or delete records from the connected Supabase database, potentially leading to total data loss or unauthorized disclosure. Organizations running self-hosted n8n instances with Supabase integrations are advised to update to the patched versions immediately to mitigate the risk of unauthorized database operations.

## Impact

Successful exploitation of this vulnerability can lead to critical data integrity and confidentiality failures. Attackers can perform unauthorized CRUD (Create, Read, Update, Delete) operations on Supabase table rows. Depending on the database configuration and connected services, this could result in mass exfiltration of sensitive information, accidental or malicious destruction of production data, or manipulation of business logic executed via n8n workflows.

## Recommendation

- Upgrade n8n instances to versions 1.123.80, 2.39.6, or 2.40.1 or higher as specified by the vendor security advisory.
- Review Supabase node configurations in existing workflows to ensure that inputs mapped to filters are treated as untrusted and properly validated by downstream workflow logic.
- Patch CVE-2026-103248 on all self-hosted n8n instances immediately.
