---
title: Authorization Bypass in Ghostwriter Report Template Swap Endpoint
slug: 2026-08-ghostwriter-auth-bypass
description: Ghostwriter versions prior to 7.1.2 are vulnerable to an authorization bypass via the report template swap endpoint, allowing authenticated attackers to enumerate and exfiltrate sensitive client-scoped template contents.
date: "2026-08-24T01:40:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - authorization-bypass
  - cve-2026-78203
vendors:
  - GhostManager
products:
  - Ghostwriter (< 7.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ghostwriter before 7.1.2 fails to validate template ownership in the report template swap endpoint, allowing attackers to attach client-scoped templates from other clients to their own reports.
    confidence_band: high
cves:
  - id: CVE-2026-78203
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78203
  - https://www.vulncheck.com/advisories/ghostwriter-before-cross-client-report-template-disclosure-via-unauthorized-template-swap
  - https://github.com/GhostManager/Ghostwriter/commit/5b2a4a297e44c823c16f65b1ba101c742791cd0b
---

Ghostwriter, a reporting platform often used by security service providers, contains an authorization bypass vulnerability (CVE-2026-78203) in its report template swap functionality. The flaw exists in versions prior to 7.1.2. The underlying issue, identified as CWE-639 (Authorization Bypass Through User-Controlled Key), stems from the application's failure to properly validate template ownership when a user initiates a template swap.

An authenticated attacker can exploit the predictable, sequential primary keys used to identify templates within the database. By iteratively manipulating these identifiers in requests to the swap endpoint, an attacker can associate templates belonging to other clients with their own report projects. Once the unauthorized template is attached, the attacker can trigger the report generation process to disclose sensitive contents, including corporate letterheads, proprietary boilerplate text, and specific project methodologies. This vulnerability poses a significant risk to organizations that store sensitive reporting artifacts within the Ghostwriter environment.

## Attack Chain

1. The attacker authenticates to the Ghostwriter application as a standard user.
2. The attacker identifies the report template swap endpoint within the application's reporting module.
3. The attacker observes the template ID parameter being passed in the HTTP request to the swap endpoint.
4. The attacker enumerates sequential integers for the template ID parameter to identify IDs belonging to other clients.
5. The attacker sends a crafted POST request to the swap endpoint containing a foreign template ID, bypassing the intended ownership validation.
6. The application incorrectly associates the foreign template with the attacker's project, confirming the bypass.
7. The attacker invokes the report generation functionality to export the report incorporating the foreign template.
8. The final report is retrieved, disclosing the contents of the unauthorized client's template.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive client information stored within report templates. This includes sensitive boilerplate text, confidential methodology, and visual assets like corporate letterheads. Given the nature of Ghostwriter as a security reporting platform, this impact could lead to the exposure of highly sensitive project details across multiple clients, potentially undermining the integrity and confidentiality of the victim organization's security engagements.

## Recommendation

* Upgrade all instances of Ghostwriter to version 7.1.2 or later to remediate the vulnerability (CVE-2026-78203).
* Review audit logs for the reporting module to identify any anomalous template swapping activity where the requesting user does not match the template owner.
* Audit existing template configurations to ensure that sensitive methodologies or boilerplate content are not being improperly exposed to users with insufficient privileges.
