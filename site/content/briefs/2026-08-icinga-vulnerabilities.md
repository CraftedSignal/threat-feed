---
title: Multiple Vulnerabilities in Icinga Web
slug: 2026-08-icinga-vulnerabilities
description: Remote attackers can exploit multiple vulnerabilities in Icinga Web to conduct Denial of Service attacks or disclose sensitive information due to improper request handling.
date: "2026-08-18T14:50:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:degamisu:open-irs:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - webserver
vendors:
  - Icinga
products:
  - Icinga Web
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein Angreifer kann mehrere Schwachstellen in Icinga ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-24757
    cvss: 7.6
    epss: 0.00527
  - id: CVE-2024-24758
    cvss: 3.9
    epss: 0.00765
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2885
  - https://nvd.nist.gov/vuln/detail/CVE-2024-24757
  - https://nvd.nist.gov/vuln/detail/CVE-2024-24758
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Icinga Web to the version addressing CVE-2024-24757 and CVE-2024-24758
      owner: IT Operations
      addresses: CVE-2024-24757, CVE-2024-24758
      evidence: Vendor security advisory
---

Icinga has announced multiple security vulnerabilities (CVE-2024-24757 and CVE-2024-24758) affecting Icinga Web. These flaws allow a remote, unauthenticated attacker to impact the availability of the monitoring interface through Denial of Service (DoS) conditions or gain access to unauthorized information. The vulnerabilities stem from improper request handling within the application's logic. Defenders should prioritize patching Icinga Web instances to the latest vendor-provided version to mitigate the risk of service interruption and potential data exposure.

## Impact

Successful exploitation of these vulnerabilities can lead to a complete loss of availability for the Icinga monitoring system, hindering operational visibility. Additionally, the disclosure of sensitive information can lead to further reconnaissance opportunities for an attacker. These vulnerabilities affect all deployments of Icinga Web where the vulnerable code paths are reachable by remote requests.

## Recommendation

* Apply vendor security patches for CVE-2024-24757 and CVE-2024-24758 immediately across all Icinga Web installations.
* Audit web server access logs for anomalous request patterns targeting Icinga Web endpoints that result in repeated 5xx status codes, which may indicate attempted DoS exploitation.
