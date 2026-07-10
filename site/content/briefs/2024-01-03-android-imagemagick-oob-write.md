---
title: Android-ImageMagick7 Out-of-Bounds Write Vulnerability (CVE-2026-4756)
slug: 2024-01-03-android-imagemagick-oob-write
description: CVE-2026-4756 is an out-of-bounds write vulnerability in MolotovCherry Android-ImageMagick7 affecting Android-ImageMagick7 versions before 7.1.2-11, potentially leading to arbitrary code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-4756
  - out-of-bounds write
  - android
  - imagemagick
vendors:
  - MolotovCherry
products:
  - Android-ImageMagick7
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4756
  - https://github.com/MolotovCherry/Android-ImageMagick7/pull/194
rules:
  - title: Suspicious ImageMagick Process Invocation
    description: Detects suspicious invocations of ImageMagick's 'convert' command with potentially malicious arguments.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
  - title: Android ImageMagick Library Loading
    description: Detects loading of the Android ImageMagick library in suspicious processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - image_load
      - android
rules_count: 2
---

CVE-2026-4756 is an out-of-bounds write vulnerability present in MolotovCherry's Android-ImageMagick7 library.  Specifically, versions prior to 7.1.2-11 are affected.  This vulnerability could allow a malicious actor to write data outside the intended memory buffer while processing image files.  Successful exploitation could potentially lead to arbitrary code execution on the affected Android device. Given the widespread use of Android devices, and the potential for exploitation via malicious image files, this is a significant vulnerability for defenders to be aware of and mitigate.  The vulnerability was reported by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG).

## Attack Chain

1.  The attacker crafts a specially crafted image file designed to trigger the out-of-bounds write in Android-ImageMagick7.
2.  The victim downloads or receives the malicious image file (e.g., via MMS, email, or a malicious website).
3.  An application on the Android device (e.g., an image viewer, a social media app, or even the operating system itself) uses the vulnerable Android-ImageMagick7 library to process the image.
4.  During image processing, the vulnerability is triggered, leading to an out-of-bounds write to memory.
5.  The attacker overwrites critical data structures in memory, potentially including function pointers or other executable code.
6.  The attacker gains control of the program execution flow by manipulating the overwritten memory.
7.  The attacker injects and executes arbitrary code on the device.
8.  The attacker achieves persistence, exfiltrates sensitive data, or performs other malicious activities.

## Impact

Successful exploitation of CVE-2026-4756 can lead to arbitrary code execution on the affected Android device. This could allow an attacker to gain full control of the device, steal sensitive data (e.g., contacts, photos, financial information), install malware, or use the device as part of a botnet. The impact is significant due to the widespread use of Android devices and the potential for exploitation via common communication channels like MMS and email.  A successful widespread attack could compromise a large number of devices.

## Recommendation

*   Upgrade Android-ImageMagick7 to version 7.1.2-11 or later to patch CVE-2026-4756.
*   Monitor application logs for errors related to image processing with Android-ImageMagick7 that could indicate exploitation attempts (reference application logging).
*   Implement runtime protections such as address space layout randomization (ASLR) and data execution prevention (DEP) to make exploitation more difficult.
*   Consider using a mobile threat detection solution that can identify and block malicious image files.
