---
title: ABB B&R PCs Vulnerable to Multiple Attacks via EDK2 Network Package
slug: 2026-05-abb-br-pcs-vulns
description: Multiple vulnerabilities in ABB B&R PCs, specifically within the EDK2 Network Package, can be exploited by a network attacker to execute remote code, initiate DoS attacks, conduct DNS cache poisoning, or extract sensitive information (CVE-2023-45229, CVE-2023-45230, CVE-2023-45231, CVE-2023-45232, CVE-2023-45233, CVE-2023-45234, CVE-2023-45235, CVE-2023-45236, CVE-2023-45237).
date: "2026-05-21T16:10:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*
tags:
  - ics
  - vulnerability
  - network
vendors:
  - ABB
products:
  - APC4100
  - APC910
  - C80
  - MPC3100
  - PPC1200
  - PPC900
  - APC2200
  - PPC2200
  - APC3100
  - PPC3100
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-45230
    cvss: 8.3
    epss: 0.00307
  - id: CVE-2023-45235
    cvss: 8.3
    epss: 0.00396
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02
  - https://www.cve.org/CVERecord?id=CVE-2023-45229
  - https://www.cve.org/CVERecord?id=CVE-2023-45230
  - https://www.cve.org/CVERecord?id=CVE-2023-45231
  - https://www.cve.org/CVERecord?id=CVE-2023-45232
  - https://www.cve.org/CVERecord?id=CVE-2023-45233
  - https://www.cve.org/CVERecord?id=CVE-2023-45234
  - https://www.cve.org/CVERecord?id=CVE-2023-45235
  - https://www.cve.org/CVERecord?id=CVE-2023-45236
  - https://www.cve.org/CVERecord?id=CVE-2023-45237
  - https://help.br-automation.com/#/en/6/cyber-security/defense-in-depth-for-br-products/reference_architecture.html
rules:
  - title: Detect CVE-2023-45229 Exploitation Attempt — Malformed DHCPv6 IA_NA/IA_TA Option
    description: Detects CVE-2023-45229 exploitation attempt — monitors network traffic for DHCPv6 Advertise messages with malformed IA_NA or IA_TA options indicative of an out-of-bounds read attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect CVE-2023-45230 Exploitation Attempt — Long DHCPv6 Server ID Option
    description: Detects CVE-2023-45230 exploitation attempt — monitors network traffic for DHCPv6 client messages with a server ID option exceeding a reasonable length, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

ABB has identified multiple vulnerabilities within the EDK2 Network Package used in several B&R PC product lines, affecting versions prior to the listed fixes. These vulnerabilities, discovered in 2023, stem from improper handling of network messages, specifically within the Preboot eXecution Environment (PXE) of the UEFI firmware. Successful exploitation could allow a network attacker to perform a variety of malicious actions including remote code execution, denial-of-service attacks, DNS cache poisoning, and sensitive information disclosure. The affected product lines include APC4100, APC910, C80, MPC3100, PPC1200, PPC900, APC2200, PPC2200, APC3100, and PPC3100. It is critical to apply the provided updates or mitigations to prevent potential exploitation. These vulnerabilities impact organizations that use these PCs in their industrial control systems.

## Attack Chain

1. The attacker identifies a vulnerable ABB B&R PC on the network running an affected firmware version.
2. The attacker crafts a malicious DHCPv6 Advertise message with a malformed IA_NA or IA_TA option (CVE-2023-45229).
3. The attacker sends the crafted DHCPv6 message to the target PC.
4. The vulnerable EDK2 Network Package processes the malicious option, resulting in an out-of-bounds read.
5. The attacker exploits the out-of-bounds read to leak sensitive information from the device's memory.
6. Alternatively, the attacker crafts a malicious DHCPv6 client message with a long server ID option (CVE-2023-45230).
7. The vulnerable EDK2 Network Package processes the oversized server ID, leading to a buffer overflow.
8. The attacker leverages the buffer overflow to achieve remote code execution on the target system, potentially leading to complete system compromise.

## Impact

Successful exploitation of these vulnerabilities could have significant consequences. An attacker could gain unauthorized access to the targeted industrial control systems, leading to disruption of operations, data theft, or the execution of malicious code. The vulnerabilities could also be leveraged to perform denial-of-service attacks, rendering the affected systems unavailable. Given that the affected PCs are used within critical infrastructure sectors like energy, the impact could extend to broader societal consequences.

## Recommendation

*   Apply the vendor-provided fixes for each affected product line (APC4100, C80, MPC3100, PPC1200, PPC900, APC2200, PPC2200, APC3100, PPC3100) as detailed in the advisory.
*   For APC910, where no patch is available, disable the vulnerable Preboot eXecution Environment (PXE) of the UEFI firmware as a mitigation.
*   If PXE functionality is required, restrict network traffic to legitimate users and block illegitimate PXE traffic, specifically related to IPv6, using a control network firewall.
*   Monitor network traffic for malformed DHCPv6 Advertise messages or DHCPv6 client messages with excessively long server IDs to detect potential exploitation attempts.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts of CVE-2023-45229 and CVE-2023-45230.
