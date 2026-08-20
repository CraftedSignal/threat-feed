---
title: SSRF Vulnerability in AeternaLabsHQ PullMD
slug: 2026-08-pullmd-ssrf
description: AeternaLabsHQ PullMD version 3.2.0 contains a Server-Side Request Forgery vulnerability in the REST API endpoint that allows remote attackers to perform unauthorized outbound requests.
date: "2026-08-20T03:09:27Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - AeternaLabsHQ
products:
  - PullMD (3.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument url leads to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-76795
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76795
rules:
  - title: Detects CVE-2026-76795 Exploitation - SSRF in PullMD /api
    description: Detects suspicious manipulation of the 'url' argument in the /api endpoint of PullMD which indicates an SSRF attempt
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch AeternaLabsHQ PullMD to version 3.3.0
      owner: IT Operations
      due: 72h
      evidence: Upgrading to version 3.3.0 will fix this issue.
  mitigation_plan:
    - priority: immediate
      action: Enable egress filtering for web servers
      owner: IT Operations
      addresses: CVE-2026-76795
      evidence: Prevent internal resource access if exploitation occurs
---

AeternaLabsHQ PullMD version 3.2.0 is affected by a Server-Side Request Forgery (SSRF) vulnerability. The vulnerability resides within the REST API component, specifically involving the /api endpoint. An attacker can exploit this by manipulating the 'url' argument, which the application fails to adequately sanitize or validate. This flaw allows remote, unauthenticated actors to force the server to make arbitrary HTTP requests to internal or external resources, potentially leading to unauthorized data access, network scanning, or interaction with internal services that are not directly exposed to the internet. The vulnerability has been addressed in version 3.3.0, and users are strongly advised to upgrade to this version to mitigate the risk associated with CVE-2026-76795.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.3, indicating a significant risk. If exploited, an attacker could abuse the PullMD server as a proxy to reach internal network segments, bypass firewall controls, or access metadata services (like IMDS in cloud environments) to steal credentials or sensitive application data.

## Recommendation

* Upgrade AeternaLabsHQ PullMD to version 3.3.0 immediately as specified in the vendor security advisory.
* Implement egress filtering at the network level for the server hosting PullMD to restrict outbound connections to only necessary and known-good external domains or IP addresses.
* Deploy the Sigma rule below to monitor for suspicious requests to the /api endpoint containing anomalous 'url' parameters.
