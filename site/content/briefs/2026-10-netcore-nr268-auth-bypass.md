---
title: Authentication Bypass in Netcore NR268
slug: 2026-10-netcore-nr268-auth-bypass
description: The user_ok function in the Netcore NR268 CGI execution component contains an authentication bypass vulnerability, CVE-2026-108907, which allows remote attackers to gain unauthorized access.
date: "2026-10-12T18:31:18Z"
lastmod: "2026-10-12T22:39:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:netcore:nr268:1.7.121109:*:*:*:*:*:*:*
tags:
  - cve-2026-108907
  - authentication-bypass
  - remote-code-execution
  - network-security
  - cve-2026-108906
  - web-vulnerability
  - cve
  - embedded-device
vendors:
  - Netcore
products:
  - NR268 (1.7.121109)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Executing a manipulation of the argument Hostname can lead to argument injection.
    confidence_band: high
cves:
  - id: CVE-2026-108907
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108907
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108906
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108929
rules:
  - title: Detects CVE-2026-108929 Exploitation - Argument Injection in DDNSset.cgi
    description: Detects exploitation attempts against CVE-2026-108929 by identifying shell metacharacters in the Hostname parameter of the DDNSset.cgi script.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1202
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate all Netcore NR268 devices from the internet to prevent remote exploitation.
      owner: IT Operations
      due: 24h
      evidence: CVSS 10.0 rating and remote exploitability.
  mitigation_plan:
    - priority: immediate
      action: Replace legacy Netcore NR268 hardware as no vendor patch exists.
      owner: IT Operations
      addresses: CVE-2026-108907
      evidence: Vendor did not respond to disclosure.
updates:
  - at: "2026-10-12T18:33:32Z"
    level: L2
    summary: added coverage for NR268 (1.7.121109)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108906
  - at: "2026-10-12T22:39:01Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-108929 Exploitation - Argument Injection in DDNSset.cgi'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108929
---

CVE-2026-108907 is an authentication bypass vulnerability affecting Netcore NR268 version 1.7.121109. The vulnerability resides in the user_ok function within the device's CGI execution component. This flaw permits an unauthenticated, remote attacker to manipulate the authentication logic, effectively bypassing security controls. The vulnerability has been publicly disclosed and is considered exploitable in the wild. Despite prior notification, the vendor has not provided a response or a corrective update, leaving deployments of this legacy firmware vulnerable to unauthorized device access and potential takeover.

## Impact

Successful exploitation of this vulnerability grants an attacker unauthorized access to the affected Netcore NR268 router. Given the CVSS v3.1 base score of 10.0, the impact includes full loss of confidentiality, integrity, and availability. Attackers can leverage this access to modify device configurations, intercept traffic, or pivot into the internal network. There are no known patches, and organizations are advised to isolate these devices from public-facing networks.

## Recommendation

Prioritized actions for security teams:
- Isolate all affected Netcore NR268 devices from the public-facing internet to mitigate the risk of remote exploitation.
- Audit network logs for anomalous traffic directed at CGI-related endpoints or authentication parameters on internal Netcore hardware.
- Replace legacy hardware, such as the Netcore NR268 running firmware 1.7.121109, that no longer receives security support from the manufacturer.
