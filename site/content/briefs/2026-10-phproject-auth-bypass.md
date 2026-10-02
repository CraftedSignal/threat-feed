---
title: Phproject REST API Authorization Bypass
slug: 2026-10-phproject-auth-bypass
description: Phproject versions before 1.8.7 contain a missing object-level authorization vulnerability in REST API issue endpoints that allows authenticated attackers to bypass security restrictions.
date: "2026-10-02T20:27:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phproject:phproject:*:*:*:*:*:*:*:*
vendors:
  - Phproject
products:
  - Phproject (< 1.8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592.002
    technique_name: 'Gather Victim Org Information: Email Addresses'
    evidence: Attackers can use a valid API key to read restricted issue contents and comments, including owner and author email addresses.
    confidence_band: high
cves:
  - id: CVE-2026-104991
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104991
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Phproject to 1.8.7 or later
      owner: IT Operations
      addresses: CVE-2026-104991
      evidence: Source material specifies version 1.8.7 as the fix.
---

Phproject versions prior to 1.8.7 are susceptible to a missing object-level authorization vulnerability within the REST API. Specifically, the endpoints identified as single_get, single_comments, and single_comments_post fail to invoke the necessary allowAccess() authorization routine. This flaw permits an attacker in possession of a valid API key to circumvent the security.restrict_access confidentiality control. By exploiting this oversight, an attacker can access sensitive information, such as issue contents and author email addresses, to which they are not authorized. Furthermore, the vulnerability allows for the unauthorized submission of comments to restricted issues. This impacts the integrity and confidentiality of project data stored within the Phproject instance. Defenders should verify the version of their Phproject deployment and upgrade to 1.8.7 or later to remediate this authorization defect.

## Impact

Successful exploitation allows authenticated users to access restricted project data and modify issue comments, potentially leading to unauthorized data exfiltration or manipulation of project records. The severity is assessed as high due to the potential for unauthorized access to sensitive user metadata and internal project communications.

## Recommendation

- Patch Phproject to version 1.8.7 or later immediately to resolve the missing authorization logic in the REST API.
- Review access logs for the identified REST API endpoints (single_get, single_comments, single_comments_post) to identify abnormal patterns or excessive unauthorized requests by API keys.
- Audit all active API keys and rotate any keys that show evidence of anomalous usage patterns associated with these endpoints.
