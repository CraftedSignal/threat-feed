---
title: Linux AppArmor Bypass via aa-exec (CVE-2026-46331)
slug: 2026-07-apparmor-bypass
description: Adversaries can exploit CVE-2026-46331 to bypass AppArmor and unprivileged user namespace restrictions on Linux systems by abusing the `aa-exec` utility with `trinity`, `chrome`, or `flatpak` AppArmor profiles, leading to privilege escalation when the `aa-exec` binary itself is executed from a non-standard path.
date: "2026-07-24T15:28:33Z"
lastmod: "2026-07-27T19:52:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.18:-:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:5.18:rc7:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc6:*:*:*:*:*:*
tags:
  - linux
  - privilege-escalation
  - apparmor
  - cve
  - endpoint
vendors:
  - Ubuntu
products:
  - AppArmor
  - aa-exec
  - AppArmor trinity profile
  - AppArmor chrome profile
  - AppArmor flatpak profile
  - trinity
  - chrome
  - flatpak
  - userns
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The following analytic detects aa-exec being used to launch a binary under the trinity, chrome, or flatpak AppArmor profiles where the executed target is not the legitimate application those profiles are intended to confine. This behavior is consistent with abuse of userns,-carrying AppArmor profiles to bypass Ubuntu's unprivileged user namespace restrictions as seen in the CVE-2026-46331 privilege escalation exploit.
    confidence_band: high
cves:
  - id: CVE-2026-46331
    cvss: 7.8
    epss: 0.00525
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_apparmor_bypass_via_aaexec.yml
  - https://github.com/sgkdev/packet_edit_meme
  - https://tuxcare.com/blog/pedit-cow-cve/
iocs:
  - type: url
    value: https://github.com/sgkdev/packet_edit_meme
  - type: url
    value: https://tuxcare.com/blog/pedit-cow-cve/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/linux_pedit/sysmon_linux.log
ioc_counts:
  url: 3
rules:
  - title: Detects CVE-2026-46331 Exploitation - Linux AppArmor Bypass via aa-exec
    description: Detects attempts to bypass AppArmor and unprivileged user namespace restrictions on Linux systems by abusing the aa-exec utility. This rule specifically flags the execution of 'aa-exec' with '-p' and '--' arguments targeting 'trinity', 'chrome', or 'flatpak' AppArmor profiles, when the 'aa-exec' binary itself is executed from a non-standard or unexpected path not covered by known legitimate application bundle directories.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-07-27T19:52:24Z"
    level: L1
    summary: new IOCs
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_apparmor_bypass_via_aaexec.yml
---

CVE-2026-46331 describes a privilege escalation vulnerability on Linux systems, specifically targeting the `aa-exec` utility when combined with certain AppArmor profiles like `trinity`, `chrome`, or `flatpak`. This vulnerability allows attackers to bypass Ubuntu's unprivileged user namespace restrictions by tricking `aa-exec` into granting namespace-creation capabilities to an arbitrary binary, rather than the legitimate application the profile was intended to confine. Defenders should be aware that adversaries may exploit this to gain elevated privileges, enabling further compromise of the system. Detection focuses on instances where `aa-exec` is invoked with specific profile arguments (`-p`, `--`) and when the `aa-exec` binary itself is executed from unexpected or non-standard directory paths, signaling an attempt to exploit this bypass. This technique can lead to full system compromise if successful.

## Attack Chain

1. An attacker gains initial user-level access to a vulnerable Linux system.
2. The attacker identifies a `aa-exec` configuration on the system that utilizes `userns`-carrying AppArmor profiles, such as `trinity`, `chrome`, or `flatpak`.
3. The attacker crafts a malicious command that invokes `aa-exec` with arguments specifying one of the vulnerable AppArmor profiles (e.g., `-p flatpak`).
4. The crafted command includes the `--` separator, followed by a path to an arbitrary, attacker-controlled binary (e.g., a shell or a privilege escalation tool).
5. To evade detection, the attacker ensures the `aa-exec` binary itself is executed from a non-standard or unusual directory path, outside of common system locations or application bundles.
6. Upon execution, the vulnerable `aa-exec` utility is tricked into granting namespace-creation capabilities to the attacker's arbitrary binary.
7. The arbitrary binary executes with elevated privileges, bypassing AppArmor and unprivileged user namespace restrictions, achieving privilege escalation on the system.

## Impact

Successful exploitation of CVE-2026-46331 grants attackers privilege escalation on affected Linux systems, particularly Ubuntu. This can lead to a full system compromise, allowing attackers to execute arbitrary code with root privileges. The impact includes unauthorized access to sensitive data, installation of persistent backdoors, modification of system configurations, or deployment of additional malicious payloads such as ransomware or cryptocurrency miners. Organizations using vulnerable Linux distributions could face significant operational disruption and data loss.

## Recommendation

* Patch CVE-2026-46331 on all affected Ubuntu systems immediately to prevent privilege escalation.
* Deploy the `Detects CVE-2026-46331 Exploitation - Linux AppArmor Bypass via aa-exec` Sigma rule to your SIEM for early detection of exploitation attempts.
* Enable Sysmon for Linux EventID 1 to ensure process creation events are collected, which is essential for activating the detection rule.
