---
title: Information Disclosure Vulnerability in NetBox
slug: 2026-10-netbox-info-disclosure
description: An authenticated remote attacker can exploit a vulnerability in NetBox to perform information disclosure through improper request handling.
date: "2026-10-07T16:54:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:netbox_labs:netbox:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - web-application
  - vulnerability
vendors:
  - NetBox Labs
products:
  - NetBox
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A vulnerability in NetBox allows a remote, authenticated attacker to perform information disclosure.
    confidence_band: high
cves:
  - id: CVE-2024-43403
    cvss: 8.8
    epss: 0.00515
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3759
  - https://nvd.nist.gov/vuln/detail/CVE-2024-43403
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch NetBox to the latest version.
      owner: IT Operations
      due: 72h
      evidence: General patch management best practice for information disclosure vulnerabilities.
  hunt_leads:
    - lead: Anomalous GET requests to API endpoints from authenticated users
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: defer
      evidence: Vulnerability allows information disclosure via crafted requests.
  mitigation_plan:
    - priority: immediate
      action: Review access logs for authenticated users requesting unusual data paths.
      owner: SOC
      addresses: CVE-2024-43403
      evidence: Vulnerability requires authentication.
---

NetBox Labs has identified a security vulnerability in NetBox that allows for unauthorized information disclosure. A remote, authenticated attacker can leverage this flaw by sending specifically crafted requests to the application. The vulnerability stems from improper handling of certain data requests, which results in the exposure of sensitive information that should otherwise be restricted. This issue impacts the confidentiality of the environment metadata and configuration data stored within the platform. Defenders should prioritize auditing internal access to the NetBox application and reviewing server logs for anomalous patterns during authenticated sessions to identify potential attempts to exploit this information disclosure vulnerability.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to gain unauthorized access to sensitive information stored within the NetBox instance, such as network topology, infrastructure configuration, and device details. This exposure can provide an attacker with reconnaissance data necessary to facilitate further lateral movement or targeted attacks within the organization's network environment.

## Recommendation

Prioritize the identification of all internal NetBox instances and review current authentication and authorization logs. Ensure the application is patched to the latest version provided by NetBox Labs to mitigate the information disclosure flaw. Monitor web access logs for unusual patterns of GET requests to metadata-sensitive endpoints by existing user accounts that deviate from established administrative or service account behavior.
