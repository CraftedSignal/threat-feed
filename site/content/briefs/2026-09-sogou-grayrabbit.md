---
title: UNC3569 Exploitation of Sogou Input Method to Deploy GRAYRABBIT Backdoor
slug: 2026-09-sogou-grayrabbit
description: UNC3569 exploited a command-line argument injection flaw in Sogou Input Method to trigger an insecure Chromium component and execute the GRAYRABBIT backdoor.
date: "2026-09-11T08:29:40Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC3569
cpes:
  - cpe:2.3:a:tencent:sogou_input_method:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - backdoor
  - exploitation
  - cve-2026-51990
  - grayrabbit
  - unc3569
vendors:
  - Tencent
products:
  - Sogou Input Method (< 16.3.0.3498)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: The attack started with a crafted link and ended with the attacker able to do anything the logged-in user could do.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: It gives an attacker a remote command shell, allows files to be moved in both directions.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: The malicious DLL was saved under the name 7-Zip loads from its own folder at startup, so running 7-Zip loaded the attacker's code instead.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The backdoor reaches its server at mail.uaiubifas.top on port 443.
    confidence_band: high
cves:
  - id: CVE-2021-38003
    cvss: 8.8
    epss: 0.38573
references:
  - https://thehackernews.com/2026/09/china-linked-unc3569-exploited-sogou.html
iocs:
  - type: hash_sha256
    value: 29c7ee41d0cc9e07d981e451df56d0c3d37c41ac4ec10c7b516cc033ee397a63
  - type: hash_sha256
    value: 749160a2f20f82744026719cf72e483595c6aad718efa74d675a98662e02422e
  - type: hash_sha256
    value: d7a3c7eb94edc0e020f74c678743d71d61e944634aade4a67a96c3589e828b3a
  - type: domain
    value: mail.uaiubifas.top
  - type: domain
    value: noht1ng.top
  - type: ip
    value: 8.218.50.207
ioc_counts:
  domain: 2
  hash_sha256: 3
  ip: 1
rules:
  - title: Detect Suspicious Sogou Protocol Handler Usage
    description: Detects exploitation of CVE-2026-51990 where biz_helper.exe is used to launch SGMyInput.exe with suspicious command-line parameters
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Sogou Input Method to 16.3.0.3498
      owner: IT Operations
      due: 24h
      evidence: Tencent released a patch in version 16.3.0.3498
    - action: Block identified IOC domains and IP
      owner: SOC
      due: 24h
      evidence: Identified C2 domains and staging IP
  hunt_leads:
    - lead: Search for 'C:\Users\Public\Documents\' creation of 7z.dll
      technique_id: T1574.002
      data_needed:
        - File system events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malicious DLL loader (7z.dll) written to C:\Users\Public\Documents\
---

UNC3569, a China-linked hacker-for-hire group, has been observed exploiting a vulnerability (CVE-2026-51990) in the Sogou Input Method to deploy the GRAYRABBIT backdoor on Windows systems. The attack chain leverages the application's 'sgbiz:' protocol handler, which failed to sanitize command-line arguments. By passing malicious arguments to the 'biz_helper.exe' component, attackers forced an internal, outdated (Chromium 80, circa 2020), and sandbox-disabled browser component to visit an attacker-controlled site. This site delivered an exploit for CVE-2021-38003, enabling arbitrary code execution. The final payload, GRAYRABBIT, is a modular backdoor known to the threat actor for years, which performs process enumeration and exfiltration via non-TLS traffic on port 443. Tencent released a patch in version 16.3.0.3498 in April 2026. Defenders should note that while the patch prevents the argument injection, the underlying browser component remains significantly outdated.

## Attack Chain

1. The attacker convinces a user to click a crafted link using the 'sgbiz:' protocol handler.
2. Windows passes the link to 'biz_helper.exe', which fails to validate command-line arguments.
3. The handler executes 'SGMyInput.exe' with parameters pointing to an attacker-controlled URL via the application's internal Chromium-based 'skin store' window.
4. The outdated Chromium v80 component, running without sandbox protections, loads a webpage containing an exploit for CVE-2021-38003.
5. The V8 engine exploit triggers arbitrary code execution in the context of the user.
6. A downloader is executed, fetching a malicious DLL and encrypted payload from an Alibaba Cloud staging server (8.218.50.207) into 'C:\Users\Public\Documents\'.
7. The system's '7-Zip' utility is launched, triggering DLL sideloading of the malicious DLL disguised as a legitimate 7-Zip component.
8. The GRAYRABBIT backdoor (core.dll) initializes, performs process checks, and begins communication with 'mail.uaiubifas.top' over port 443 using RC4-scrambled traffic.

## Impact

The vulnerability allows unauthenticated remote code execution with user privileges. Given Sogou Input Method's massive user base, exceeding 455 million monthly users with significant deployments in government, education, finance, and technology sectors in East and Southeast Asia, the potential for widespread compromise is significant. Successful exploitation grants attackers persistent access to sensitive data, file exfiltration capabilities, and the ability to load additional malicious modules.

## Recommendation

1. Upgrade all instances of Sogou Input Method to version 16.3.0.3498 or later immediately.
2. Block the identified C2 domain 'mail.uaiubifas.top' and the staging IP '8.218.50.207' at the network perimeter.
3. Deploy the provided Sigma rule to detect the specific process-creation pattern of 'biz_helper.exe' launching 'SGMyInput.exe' with unexpected URL parameters.
4. Monitor for non-TLS traffic on port 443, which may indicate GRAYRABBIT command and control activity.
5. Hunt for artifacts in 'C:\Users\Public\Documents\' consistent with the 7-Zip DLL sideloading technique.
