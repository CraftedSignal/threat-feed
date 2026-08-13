---
title: Hardcoded Authentication Token in IBM Storage Scale GUI
slug: 2026-08-ibm-storage-scale-hardcoded-token
description: IBM Storage Scale versions 5.2.3.0 through 5.2.3.8 and 6.0.0.0 through 6.0.1.0 contain a hardcoded token used for inter-node communication and REST API authentication, allowing potential unauthenticated access to the GUI.
date: "2026-08-13T22:05:19Z"
lastmod: "2026-08-13T22:08:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - cve-2026-13460
vendors:
  - IBM
products:
  - Storage Scale 5.2.3.0 through 5.2.3.8
  - Storage Scale 6.0.0.0 through 6.0.1.0
  - Storage Scale
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: IBM Storage Scale GUI contains a hardcoded token in the source code, which was used for inter-node cluster communication and REST API authentication between GUI.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The admin password is logged into the GUI log of IBM Storage Scale Systems Deploy and Upgrade from GUI.
    confidence_band: high
cves:
  - id: CVE-2026-13460
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13460
  - https://www.ibm.com/support/pages/node/7283308
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19483
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch IBM Storage Scale to the versions recommended in the IBM security advisory.
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory 7283308
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the IBM Storage Scale GUI management port.
      owner: Network Engineering
      addresses: CVE-2026-13460
      evidence: Hardcoded credentials allow unauthenticated access via the GUI.
updates:
  - at: "2026-08-13T22:08:47Z"
    level: L2
    summary: added coverage for Storage Scale
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19483
---

IBM has disclosed a security vulnerability (CVE-2026-13460) affecting the GUI component of IBM Storage Scale. The vulnerability arises from a hardcoded token embedded within the source code, which is utilized for inter-node cluster communication and REST API authentication between GUI instances. An unauthenticated, network-adjacent attacker could potentially leverage this hardcoded credential to bypass authentication mechanisms, gain unauthorized access to the management interface, or intercept/manipulate cluster communication. The vulnerability affects Storage Scale versions 5.2.3.0 through 5.2.3.8 and 6.0.0.0 through 6.0.1.0. Given the high CVSS score of 7.5, organizations deploying these versions of IBM Storage Scale should prioritize the application of vendor-provided patches to mitigate the risk of unauthorized administrative access or cluster compromise.

## Impact

Successful exploitation of this vulnerability could grant an attacker unauthorized access to the Storage Scale GUI. As the hardcoded token is used for authentication, an attacker could potentially gain administrative control over the cluster's management layer. This could lead to sensitive data exfiltration, unauthorized configuration changes, or the disruption of storage services across the affected cluster.

## Recommendation

* Apply the security patches provided by IBM in the official security advisory (https://www.ibm.com/support/pages/node/7283308) immediately.
* Audit network access controls for the Storage Scale GUI to ensure that only authorized administrative workstations or management subnets have access to the management interface.
* Monitor web server logs for suspicious API requests or unauthorized attempts to access management endpoints using static or unusual token headers.
