---
title: Arbitrary File Read and SSRF Vulnerability in Weaver e-Bridge
slug: 2026-10-weaver-ebridge-arbitrary-file-read
description: Weaver e-Bridge contains an unauthenticated arbitrary file read and SSRF vulnerability in the saveYZJFile endpoint, enabling attackers to access sensitive system files or scan internal network resources.
date: "2026-10-02T20:26:48Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:weaver:e_bridge:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - ssrf
vendors:
  - Weaver
products:
  - e-Bridge
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Weaver e-Bridge contains an unauthenticated arbitrary file read vulnerability that allows remote attackers to access arbitrary files on the host system.
    confidence_band: high
cves:
  - id: CVE-2020-37278
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37278
rules:
  - title: Detects CVE-2020-37278 Exploitation - Arbitrary File Read and SSRF via saveYZJFile
    description: Detects attempts to exploit the saveYZJFile endpoint by supplying file:// or potentially malicious URLs in the downloadUrl parameter.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms active exploitation in the wild.
  hunt_leads:
    - lead: Search web logs for 'file://' in the 'downloadUrl' parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as the specific exploitation method.
  mitigation_plan:
    - priority: immediate
      action: Patch Weaver e-Bridge as per vendor instructions.
      owner: IT Operations
      addresses: CVE-2020-37278
      evidence: NVD vulnerability disclosure.
---

Weaver e-Bridge contains a critical vulnerability (CVE-2020-37278) within its saveYZJFile endpoint that allows for both unauthenticated arbitrary file read and server-side request forgery (SSRF). By manipulating the downloadUrl parameter, a remote attacker can force the application to retrieve and expose local files, such as /etc/passwd, or leverage the server as a proxy to conduct SSRF attacks against internal network infrastructure. This vulnerability represents a significant risk for environments utilizing e-Bridge, as it facilitates credential theft, configuration leakage, and internal reconnaissance. Exploitation of this flaw has been observed in the wild since October 17, 2023, as documented by the Shadowserver Foundation. Defenders should prioritize patching and monitoring traffic directed toward the affected endpoint.

## Attack Chain

1. Attacker identifies an internet-facing instance of Weaver e-Bridge.
2. Attacker crafts an HTTP request targeting the saveYZJFile endpoint.
3. Attacker injects a file:// URI into the downloadUrl parameter to target local files (e.g., /etc/passwd).
4. The application processes the malicious parameter without sufficient input validation.
5. The server reads the content of the specified local file from the disk.
6. The server returns the contents of the file in the HTTP response body to the attacker.
7. Alternatively, the attacker injects an http(s):// URI into the downloadUrl parameter to probe internal services.
8. The server performs the request as the internal host, allowing the attacker to bypass network perimeter controls.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the host filesystem, potentially leading to full system compromise through the exposure of configuration files, keys, and credentials. Furthermore, the SSRF capability enables attackers to pivot into the internal network, perform port scanning, and interact with internal-only web services that are otherwise unreachable from the internet.

## Recommendation

- Monitor web server access logs for anomalous requests to the saveYZJFile endpoint involving file:// or unexpected URL schemes in the downloadUrl parameter.
- Deploy the provided Sigma rule to detect exploitation attempts against the vulnerable endpoint.
- Patch affected Weaver e-Bridge instances immediately as updates become available from the vendor.
- Restrict network access to the saveYZJFile endpoint at the firewall level if immediate patching is not possible.
