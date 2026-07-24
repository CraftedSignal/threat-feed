---
title: 'Poweradmin: Broken Access Control (IDOR) Allows DNS Record Modification'
slug: 2026-07-poweradmin-idor
description: A low-privilege authenticated user in Poweradmin (a web front-end for PowerDNS) can exploit an Insecure Direct Object Reference (IDOR) vulnerability, allowing them to modify any DNS record on the server, even those they do not own, by manipulating POST request parameters to bypass access control checks and achieve DNS record repointing, disabling, or hijacking, leading to data integrity and availability issues, and potentially cross-tenant DNS takeover.
date: "2026-07-24T21:57:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - idor
  - dns-takeover
  - web-application
  - vulnerability
  - access-control
vendors:
  - Poweradmin
products:
  - Poweradmin (< 3.9.11)
  - Poweradmin (< 4.2.5)
  - Poweradmin (< 4.3.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Repointing or corrupting other customers' / other departments' DNS records (integrity).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A low-privilege "Editor" who only owns `attacker.example` was able to overwrite a record living in `victim.example` (owned by the admin), even though the same account gets a flat "you do not have permission to access this zone" if it tries to open that zone directly.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Any authenticated user who owns at least one zone can tamper with records in every other zone on the server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rm67-g9ch-vxff
iocs:
  - type: domain
    value: attacker.example
  - type: domain
    value: victim.example
  - type: ip
    value: 1.1.1.1
  - type: ip
    value: 6.6.6.6
  - type: domain
    value: pwned.attacker.example
ioc_counts:
  domain: 3
  ip: 2
---

A critical Insecure Direct Object Reference (IDOR) vulnerability (GHSA-rm67-g9ch-vxff) has been disclosed in Poweradmin, a web front-end for PowerDNS. Discovered by Saif Salah, this flaw allows any authenticated user possessing ownership of at least one DNS zone to arbitrarily modify, disable, or hijack DNS records in any other zone managed by the server, regardless of their legitimate access permissions. The vulnerability, present across Poweradmin versions prior to 3.9.11, 4.2.5, and 4.3.4, stems from a logical error in the `RecordManager::editRecord()` function. Access control checks are performed against an attacker-controlled zone ID, while the actual record modification is applied to a different, attacker-controlled record ID without verifying their association. This can lead to a full cross-tenant DNS takeover in shared or multi-tenant environments, posing significant risks to DNS integrity and service availability.

## Attack Chain

1. An attacker, authenticated with a low-privilege "Editor" account, owns at least one DNS zone (e.g., `attacker.example`, zone ID 3).
2. The attacker identifies a target DNS record in a zone they do not own (e.g., `www.victim.example` with record ID 5, residing in `victim.example` with zone ID 2).
3. The attacker navigates to their own zone's edit page (e.g., `/zones/3/edit`) and initiates a record save action using an intercepting proxy.
4. Within the `POST /zones/3/edit` request body, the attacker manipulates parameters, specifically setting `record[5][rid]=5` (the victim's record ID) and `record[5][zid]=3` (the attacker's legitimate zone ID).
5. The Poweradmin application performs an ownership check using `record[5][zid]=3` from the request, which passes successfully due to the attacker's legitimate ownership of zone 3.
6. The application proceeds to modify the record using `record[5][rid]=5` without verifying that this record (ID 5) actually belongs to zone ID 3, thus overwriting the victim's DNS record (e.g., changing `www.victim.example` content to `6.6.6.6`).
7. The attacker successfully modifies a DNS record in a zone they are not authorized to access, demonstrating a bypass of intended access controls and potentially leading to DNS takeover.

## Impact

Successful exploitation of this IDOR vulnerability allows an authenticated attacker to compromise the integrity and availability of DNS records across the entire Poweradmin installation. Attackers can repoint DNS records (e.g., `pwned.attacker.example`) to malicious infrastructure, corrupt existing records, or silently disable critical services by setting the `disabled` flag. In multi-tenant or shared hosting environments, this directly translates to cross-tenant DNS takeover, where one customer's records can be hijacked or disrupted by another using their `attacker.example` domain. This poses a significant threat to an organization's online presence, email delivery, and other services reliant on accurate DNS resolution, potentially leading to widespread service outages or redirection to phishing/malware sites. The attacker's own valid CSRF token and zone serial satisfy all form-level checks, making the malicious request appear legitimate to the application.

## Recommendation

* Patch Poweradmin installations immediately to versions 3.9.11, 4.2.5, or 4.3.4 or later to address the vulnerability described in the GHSA-rm67-g9ch-vxff advisory.
* Implement server-side validation, as suggested in the GHSA-rm67-g9ch-vxff advisory, to ensure the record ID being modified truly belongs to the zone ID used for access checks.
* Review web server access logs for anomalous `POST /zones/*/edit` requests, paying attention to the context around the `rid` and `zid` parameters in the request body for evidence of the IDOR identified in the attack chain.
