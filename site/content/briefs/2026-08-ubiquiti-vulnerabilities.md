---
title: Critical Vulnerabilities in Ubiquiti UniFi Product Suite
slug: 2026-08-ubiquiti-vulnerabilities
description: Multiple high-severity vulnerabilities, including CVE-2026-77533 and CVE-2026-77537, affect Ubiquiti UniFi products, potentially allowing for system compromise.
date: "2026-08-27T12:39:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - network-security
vendors:
  - Ubiquiti
products:
  - UniFi Protect
  - UniFi OS
  - UniFi Network Application
cves:
  - id: CVE-2026-77533
    cvss: 9.9
    epss: 0.01015
  - id: CVE-2026-77537
    cvss: 10
references:
  - https://www.ncsc.nl/alerts/ernstige-kwetsbaarheden-in-ubiquiti-unifi-producten
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of UniFi Protect, UniFi OS, and UniFi Network Application
      owner: IT Operations
      due: 48h
      evidence: NCSC-NL recommendation to install security updates as soon as possible
  mitigation_plan:
    - priority: immediate
      action: Remove vulnerable management interfaces from public-facing exposure
      owner: IT Operations
      addresses: CVE-2026-77533, CVE-2026-77537
---

The Netherlands National Cyber Security Centre (NCSC-NL) has issued an advisory regarding multiple critical vulnerabilities discovered in the Ubiquiti UniFi ecosystem, specifically impacting UniFi Protect, UniFi OS, and the UniFi Network Application. Among the identified issues are CVE-2026-77533 and CVE-2026-77537, which have been assigned CVSS scores reaching 10.0. While the NCSC currently assesses the probability of exploitation as medium, the potential impact on compromised systems is considered high. These vulnerabilities require immediate patching to prevent unauthorized access or system-level compromise. Ubiquiti has released security updates to address these flaws across the affected product lines. Defenders are advised to audit their environments for these products and prioritize the application of available firmware and software patches to remediate the risks associated with these CVEs.

## Impact

The vulnerabilities affect critical infrastructure components, including network controllers and OS management interfaces. If successfully exploited, these flaws could allow attackers to bypass authentication, achieve remote code execution, or gain administrative control over managed networks. Given the deployment profile of these products, successful exploitation poses a significant risk to organizational internal network visibility and control.

## Recommendation

Prioritize the immediate patching of all instances of UniFi Protect, UniFi OS, and the UniFi Network Application to the latest versions provided by Ubiquiti. Organizations should verify the version numbers against the specific manufacturer security advisory to ensure the mitigation of CVE-2026-77533 and CVE-2026-77537. Perform an inventory scan to identify all exposed Ubiquiti devices on the network perimeter and ensure they are not accessible to the public internet unless necessary.
