---
brief_id: brief-2026-11-12-citrix-secure-access-vulns
event_id: brief-2026-11-12-citrix-secure-access-vulns
revision: 1
activity_at: "2026-11-12T16:26:20Z"
title: 'Citrix Secure Access Client: Privilege Escalation Vulnerabilities'
slug: 2026-11-citrix-secure-access-vulns
description: Multiple vulnerabilities in Citrix Secure Access client allow an attacker to provoke an elevation of privileges.
date: "2026-11-12T16:26:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cves:
  - id: CVE-2026-118268
    kev_status: unknown
  - id: CVE-2026-118269
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1519/
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697280&articleURL=Citrix_Secure_Access_Client_for_Windows_Security_Bulletin_for_CVE_2026_118268
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697281&articleURL=Citrix_Secure_Access_Client_for_Linux_Security_Bulletin_for_CVE_2026_118269
  - https://www.cve.org/CVERecord?id=CVE-2026-118268
  - https://www.cve.org/CVERecord?id=CVE-2026-118269
---

Multiple vulnerabilities have been identified in the Citrix Secure Access client, which may allow an attacker to cause an elevation of privileges. These issues are detailed in Citrix security bulletins CTX697280 and CTX697281.

## Impact
Successful exploitation may allow an attacker to gain elevated privileges on affected systems.

## Recommendation
Refer to the official Citrix security bulletins for further details and to obtain available patches.
