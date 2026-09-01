---
title: Malicious Packagist Composer Themes Deploying iOS Spyware
slug: 2026-09-packagist-ios-spyware
description: Threat actors are distributing 13 malicious Composer themes via Packagist to compromise streaming websites and deploy a WebKit-to-kernel exploit chain against iOS visitors for data exfiltration and cryptocurrency wallet theft.
date: "2026-09-01T15:09:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:visionos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:watchos:*:*:*:*:*:*:*:*
  - cpe:2.3:a:webkitgtk:webkitgtk:*:*:*:*:*:*:*:*
  - cpe:2.3:a:wpewebkit:wpe_webkit:*:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:6.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_aus:8.2:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_aus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_aus:8.6:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_els:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:8.4:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:8.6:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux_eus:9.4:*:*:*:*:*:*:*
tags:
  - supply-chain
  - mobile-malware
  - web-security
  - cryptocurrency-theft
  - ios
  - spyware
vendors:
  - Apple
products:
  - iOS (< 18.7.3)
  - macOS (< 26.1)
affected_os:
  - iOS 18.4
  - iOS 18.5
  - iOS 18.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: Cybersecurity researchers have identified a set of 13 malicious Composer theme packages on Packagist that are designed to inject JavaScript into Vietnamese movie and comic streaming sites.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: At a high level, the trojanized Composer theme injects JavaScript that runs a mobile gambling and ad-fraud redirect.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Specifically, it weaponizes two WebKit vulnerabilities -- CVE-2025-31277 ... and CVE-2025-43529 ... in a manner that's analogous to the DarkSword exploit kit.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: On success, the final payload uses the kernel read to collect keychain databases, Wi-Fi passwords, the SMS database, the address book, Photos, browser cookies, call history, location history, and account databases.
    confidence_band: high
cves:
  - id: CVE-2025-31277
    cvss: 8.8
    epss: 0.01481
  - id: CVE-2025-43529
    cvss: 8.8
    epss: 0.08891
references:
  - https://thehackernews.com/2026/09/13-malicious-packagist-packages-target.html
iocs:
  - type: domain
    value: cloudfareintcdn.com
ioc_counts:
  domain: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block cloudfareintcdn.com at DNS resolver.
      owner: SOC
      due: 2h
      evidence: Identified as C2 domain in brief IOC list.
    - action: 'Audit composer.json files for namespaces: vsmov, vsphim, haiau009, chilltvcms, ophimcms.'
      owner: IT Operations
      due: 24h
      evidence: Packages identified as malicious.
  mitigation_plan:
    - priority: immediate
      action: Update iOS devices to 18.7.3 or later.
      owner: IT Operations
      addresses: CVE-2025-43529
      evidence: Patched versions specified in brief.
---

Researchers have identified 13 malicious Composer theme packages hosted on Packagist that target Vietnamese movie and comic streaming sites. These packages are part of a broader campaign involving at least five vendor namespaces (vsmov, vsphim, haiau009, chilltvcms, ophimcms) that inject malicious JavaScript into websites. When a user visits an infected site on an unpatched iOS device (specifically iOS versions 18.4 through 18.6.x), the script triggers a multi-stage exploit chain. This campaign leverages infrastructure previously linked to the Funnull entity to facilitate browser-based exploitation. The final payload achieves kernel-level access on the target iPhone, enabling the exfiltration of sensitive databases, including SMS, browser cookies, Photos, and cryptocurrency wallet seeds from applications like Bitget, Phantom, and Trust Wallet. This threat is particularly notable for its use of supply chain compromise to reach end-users and the automation of financial theft via mobile browser exploitation.

## Attack Chain

1. Site administrators unknowingly install a trojanized Composer theme package from the Packagist repository.
2. The theme injects malicious JavaScript into every page served to website visitors.
3. The JavaScript performs browser-side environment fingerprinting to identify the visitor's iOS version.
4. The script retrieves a platform-specific exploit payload hosted on external infrastructure (Funnull).
5. The browser executes an exploit chain weaponizing CVE-2025-31277 and CVE-2025-43529 to escape the WebContent sandbox.
6. The exploit pivots to the GPU process and triggers a kernel vulnerability (AppleM2ScalerCSCDriver) to gain read/write privileges.
7. The final spyware payload extracts the iOS Keychain, SMS, Photos, and wallet seeds, then encrypts them using AES.
8. The stolen data is exfiltrated via HTTPS POST to a rotating pool of command-and-control domains.

## Impact

The campaign affects users of mobile Safari on iOS devices running vulnerable firmware (iOS 18.4 through 18.6.x). If successful, attackers gain complete access to the device's personal data, including Wi-Fi passwords, call history, location, and cryptocurrency assets. The use of infrastructure associated with previously sanctioned entities indicates a high-stakes financial motivation. While the exact number of victims is not publicly quantified, the campaign targets high-traffic streaming sites, suggesting a broad scope of potential compromise.

## Recommendation

1. Site operators using OphimCMS or KKPhim must audit dependencies for the identified vendor namespaces (vsmov, vsphim, haiau009, chilltvcms, ophimcms) and remove all unauthorized themes immediately.
2. Block the identified C2 domain "cloudfareintcdn.com" at the network perimeter and DNS resolver level.
3. Enforce OS updates for all mobile devices; prioritize patching iOS to 18.7.3 or later and macOS to 26.1 or later to mitigate CVE-2025-31277 and CVE-2025-43529.
4. Users should review permissions for cryptocurrency wallet applications and rotate credentials for affected accounts if their devices were running vulnerable iOS versions during the period of exposure.
