---
title: JDownloader Website Compromised to Serve Malicious Installers
slug: 2026-10-jdownloader-supply-chain
description: JDownloader's website was compromised on May 6-7, 2026, with download links repointed to malicious installers deploying a Remote Access Trojan on Windows and harmful shell commands on Linux. Users who installed from affected links should treat the system as fully compromised and perform a clean OS reinstall.
date: "2026-05-11T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - malware
  - rat
  - windows
  - linux
  - jdownloader
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: "User Execution: Malicious File"
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://jdownloader.org/incident_8.5.2026.html
  - https://news.risky.biz/risky-bulletin-fcc-relaxes-foreign-router-ban-to-allow-for-security-updates/
iocs:
  - type: sha256
    value: 6d975c05ef7a164707fa359284a31bfe0b1681fe0319819cb9e2c4eec2a1a8af
    description: "Malicious JDownloader2Setup_unix_nojre.sh (Linux installer)"
  - type: sha256
    value: fb1e3fe4d18927ff82cffb3f82a0b4ffb7280c85db5a8a8b6f6a1ac30a7e7ed9
    description: "Malicious JDownloader2Setup_windows-amd64_v11_0_30.exe"
  - type: sha256
    value: 04cb9f0bca6e0e4ed30bc92726590724bf60938440b3825252657d1b3af45495
    description: "Malicious JDownloader2Setup_windows-amd64_v17_0_18.exe"
  - type: sha256
    value: 5a6636ce490789d7f26aaa86e50bd65c7330f8e6a7c32418740c1d009fb12ef3
    description: "Malicious JDownloader2Setup_windows-amd64_v1_8_0_482.exe"
  - type: sha256
    value: 32891c0080442bf0a0c5658ada2c3845435b4e09b114599a516248723aad7805
    description: "Malicious JDownloader2Setup_windows-amd64_v21_0_10.exe"
  - type: sha256
    value: de8b2bdfc61d63585329b8cfca2a012476b46387435410b995aeae5b502bd95e
    description: "Malicious JDownloader2Setup_windows-x86_v11_0_29.exe"
  - type: sha256
    value: e4a20f746b7dd19b8d9601b884e67c8166ea9676b917adea6833b695ba13de16
    description: "Malicious JDownloader2Setup_windows-x86_v17_0_17.exe"
  - type: sha256
    value: 4ff7eec9e69b6008b77de1b6e5c0d18aa717f625458d80da610cb170c784e97c
    description: "Malicious JDownloader2Setup_windows-x86_v1_8_0_472.exe"
rules:
  - title: Execution of Known Malicious JDownloader Installer by Hash
    description: Detects process creation events matching the SHA256 hashes of JDownloader installers known to be malicious from the May 6-7 2026 supply chain attack.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1195.002
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Unsigned JDownloader Installer Execution
    description: Detects execution of JDownloader setup executables that are not signed by "AppWork GmbH", which is the expected publisher for all legitimate JDownloader installers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

JDownloader, a widely used open-source download manager, had its official website compromised between May 5–7, 2026. Attackers gained access to the site's CMS and repointed specific installer download links to malicious third-party files — they did not modify the legitimate installer packages themselves, only the links serving them. The affected download paths were the Windows "Download Alternative Installer" links and the Linux shell-based installer. Both Windows and Linux variants contained a Remote Access Trojan (RAT); the Windows executables additionally lack the legitimate "AppWork GmbH" code signature present on all genuine JDownloader installers. Crucially, in-app updates were unaffected because JDownloader's update mechanism uses RSA signature verification.

## Attack Chain

1. Attackers gained unauthorized access to JDownloader's website CMS.
2. On May 5, 23:55 UTC, the attackers tested their approach on a low-traffic page.
3. On May 6, ~00:01 UTC, live download links for the Windows "Alternative Installer" variants and the Linux shell installer were repointed to attacker-controlled files hosted externally.
4. A user visiting jdownloader.org and clicking one of the affected download links received a malicious installer silently replacing the legitimate one.
5. On Windows, the malicious executable lacks the AppWork GmbH code signature but proceeds to execute as an installer; on Linux, the shell script runs harmful commands inline during installation.
6. The RAT is deployed, providing attackers with persistent remote access to the victim system.
7. On May 7, 17:06 UTC, the compromise was reported via Reddit; JDownloader shut down their servers at 17:24 UTC to stop distribution.
8. Clean, verified installers were restored on May 8–9 UTC.

## Impact

Any user who downloaded and executed a JDownloader installer via the website's "Alternative Installer" or Linux shell links between May 6 00:01 UTC and May 7 17:24 UTC should consider their system fully compromised. The deployed RAT grants attackers remote command execution, enabling credential theft, lateral movement, data exfiltration, and persistence. The JDownloader team explicitly recommends a clean OS reinstall for affected systems and warns against performing sensitive operations (banking, password management) until a clean environment is confirmed. Users who installed via the standard (non-alternative) Windows installer, macOS installer, or used in-app updates are not affected.

## Recommendation

*   If JDownloader was installed during May 6–7, 2026 via the "Alternative Installer" or Linux shell links, perform a clean OS reinstall — do not attempt to remove the malware in-place.
*   Change all passwords (email, banking, credentials managers) from a separate, verified-clean device before accessing any accounts on the potentially compromised system.
*   Block the IOC hashes listed above in your EDR and file integrity monitoring tooling.
*   Deploy the Sigma rule "Execution of Known Malicious JDownloader Installer by Hash" to identify any historical execution of these installers in your environment.
*   Deploy the Sigma rule "Unsigned JDownloader Installer Execution" as an ongoing detection for future cases where JDownloader is installed without AppWork GmbH's code signature.
*   Verify JDownloader installations in your estate by checking installer hashes or confirming the code signature on the `JDownloader2Setup_*.exe` binary against the AppWork GmbH certificate.
