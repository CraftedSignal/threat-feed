---
title: Multiple Vulnerabilities in Microsoft Edge Allow for Remote Code Execution and Security Policy Bypass
slug: 2026-05-edge-vulns
description: Multiple vulnerabilities in Microsoft Edge prior to version 148.0.3967.70 allow a remote attacker to execute arbitrary code and bypass security policies.
date: "2026-05-18T11:30:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - microsoft-edge
  - rce
  - security-bypass
vendors:
  - Microsoft
products:
  - Edge (versions prior to 148.0.3967.70)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-8518
    cvss: 8.8
    epss: 0.0008
  - id: CVE-2026-8540
    cvss: 8.8
    epss: 0.00081
  - id: CVE-2026-8558
    cvss: 8.8
    epss: 0.0008
  - id: CVE-2026-8565
    cvss: 4.7
    epss: 0.00015
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0607/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45492
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45494
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45495
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8509
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8510
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8511
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8512
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8513
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8514
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8515
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8516
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8517
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8518
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8519
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8523
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8524
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8525
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8526
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8527
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8528
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8529
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8530
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8531
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8532
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8533
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8534
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8535
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8536
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8537
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8538
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8539
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8540
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8541
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8542
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8543
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8544
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8545
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8546
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8547
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8548
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8549
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8550
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8551
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8552
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8553
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8554
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8555
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8556
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8557
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8558
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8559
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8560
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8561
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8562
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8563
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8565
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8566
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8567
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8568
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8569
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8570
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8571
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8572
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8573
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8575
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8576
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8577
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8578
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8579
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8580
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8581
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8582
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8584
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8585
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8586
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-8587
rules:
  - title: Detect Edge Process Spawning Suspicious Shell Commands
    description: Detects processes spawned by Microsoft Edge that execute suspicious shell commands, potentially indicating exploitation of CVE-2026-45492, CVE-2026-45494, CVE-2026-45495, CVE-2026-8509, CVE-2026-8510, CVE-2026-8511, CVE-2026-8512, CVE-2026-8513, CVE-2026-8514, CVE-2026-8515, CVE-2026-8516, CVE-2026-8517, CVE-2026-8518, CVE-2026-8519, CVE-2026-8523, CVE-2026-8524, CVE-2026-8525, CVE-2026-8526, CVE-2026-8527, CVE-2026-8528, CVE-2026-8529, CVE-2026-8530, CVE-2026-8531, CVE-2026-8532, CVE-2026-8533, CVE-2026-8534, CVE-2026-8535, CVE-2026-8536, CVE-2026-8537, CVE-2026-8538, CVE-2026-8539, CVE-2026-8540, CVE-2026-8541, CVE-2026-8542, CVE-2026-8543, CVE-2026-8544, CVE-2026-8545, CVE-2026-8546, CVE-2026-8547, CVE-2026-8548, CVE-2026-8549, CVE-2026-8550, CVE-2026-8551, CVE-2026-8552, CVE-2026-8553, CVE-2026-8554, CVE-2026-8555, CVE-2026-8556, CVE-2026-8557, CVE-2026-8558, CVE-2026-8559, CVE-2026-8560, CVE-2026-8561, CVE-2026-8562, CVE-2026-8563, CVE-2026-8565, CVE-2026-8566, CVE-2026-8567, CVE-2026-8568, CVE-2026-8569, CVE-2026-8570, CVE-2026-8571, CVE-2026-8572, CVE-2026-8573, CVE-2026-8575, CVE-2026-8576, CVE-2026-8577, CVE-2026-8578, CVE-2026-8579, CVE-2026-8580, CVE-2026-8581, CVE-2026-8582, CVE-2026-8584, CVE-2026-8585, CVE-2026-8586, CVE-2026-8587.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Edge Spawning WMIC Process
    description: Detects the execution of wmic.exe spawned by Microsoft Edge, which can be indicative of post-exploitation activity related to CVE-2026-45492, CVE-2026-45494, CVE-2026-45495, CVE-2026-8509, CVE-2026-8510, CVE-2026-8511, CVE-2026-8512, CVE-2026-8513, CVE-2026-8514, CVE-2026-8515, CVE-2026-8516, CVE-2026-8517, CVE-2026-8518, CVE-2026-8519, CVE-2026-8523, CVE-2026-8524, CVE-2026-8525, CVE-2026-8526, CVE-2026-8527, CVE-2026-8528, CVE-2026-8529, CVE-2026-8530, CVE-2026-8531, CVE-2026-8532, CVE-2026-8533, CVE-2026-8534, CVE-2026-8535, CVE-2026-8536, CVE-2026-8537, CVE-2026-8538, CVE-2026-8539, CVE-2026-8540, CVE-2026-8541, CVE-2026-8542, CVE-2026-8543, CVE-2026-8544, CVE-2026-8545, CVE-2026-8546, CVE-2026-8547, CVE-2026-8548, CVE-2026-8549, CVE-2026-8550, CVE-2026-8551, CVE-2026-8552, CVE-2026-8553, CVE-2026-8554, CVE-2026-8555, CVE-2026-8556, CVE-2026-8557, CVE-2026-8558, CVE-2026-8559, CVE-2026-8560, CVE-2026-8561, CVE-2026-8562, CVE-2026-8563, CVE-2026-8565, CVE-2026-8566, CVE-2026-8567, CVE-2026-8568, CVE-2026-8569, CVE-2026-8570, CVE-2026-8571, CVE-2026-8572, CVE-2026-8573, CVE-2026-8575, CVE-2026-8576, CVE-2026-8577, CVE-2026-8578, CVE-2026-8579, CVE-2026-8580, CVE-2026-8581, CVE-2026-8582, CVE-2026-8584, CVE-2026-8585, CVE-2026-8586, CVE-2026-8587.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 18, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in Microsoft Edge. These vulnerabilities, detailed in Microsoft Edge security bulletins released on May 15, 2026, can allow an attacker to remotely execute arbitrary code, bypass security policies, and trigger unspecified security issues. The vulnerabilities affect Microsoft Edge versions prior to 148.0.3967.70. Successful exploitation of these vulnerabilities could allow an attacker to gain unauthorized access and control over a targeted system.

## Attack Chain

1.  An attacker crafts a malicious web page or leverages an existing compromised website.
2.  The victim visits the malicious website or is redirected to it via phishing or other social engineering techniques.
3.  The attacker exploits one of the vulnerabilities (CVE-2026-45492, CVE-2026-45494, CVE-2026-45495, CVE-2026-8509 through CVE-2026-8519, CVE-2026-8523 through CVE-2026-8542, CVE-2026-8543 through CVE-2026-8582, CVE-2026-8584 through CVE-2026-8587) in Microsoft Edge.
4.  Successful exploitation leads to arbitrary code execution within the context of the browser process.
5.  The attacker may escalate privileges to gain further access to the system.
6.  The attacker installs malware, such as a backdoor, to maintain persistence.
7.  The attacker performs reconnaissance on the compromised system and network.
8.  The attacker exfiltrates sensitive data or performs other malicious activities.

## Impact

Successful exploitation of these vulnerabilities can lead to arbitrary code execution, potentially allowing an attacker to gain complete control over the affected system. This could result in data theft, system compromise, and further propagation of the attack within the network. Given the widespread use of Microsoft Edge, a large number of users and organizations are potentially affected.

## Recommendation

*   Apply the security updates provided by Microsoft to patch the vulnerabilities in Microsoft Edge versions prior to 148.0.3967.70 as referenced in the advisory.
*   Deploy the Sigma rule to detect potential exploitation attempts by monitoring process creations related to web browser processes and shell commands.
*   Monitor web server logs for suspicious activity that may indicate exploitation attempts targeting these vulnerabilities.
