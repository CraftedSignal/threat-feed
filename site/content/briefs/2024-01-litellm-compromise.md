---
title: Compromised Litellm PyPI Package Versions
slug: 2024-01-litellm-compromise
description: Versions 1.82.7 and 1.82.8 of the Litellm package on PyPI were compromised in a supply chain attack, potentially impacting numerous users, with recommendations to avoid updating to these versions.
date: "2026-03-24T12:12:58Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - supply-chain
  - pypi
  - litellm
  - compromise
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s2c0sj/litellm_1827_and_1828_on_pypi_are_compromised_do/
  - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
iocs:
  - type: url
    value: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
ioc_counts:
  url: 1
rules:
  - title: Suspicious Process Spawned by Python
    description: Detects suspicious processes spawned by python executables, which may indicate malicious code execution within a compromised Python package.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Python
    description: Detects suspicious outbound network connections initiated from Python processes, potentially indicating C2 activity from a compromised Python package.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 24, 2026, versions 1.82.7 and 1.82.8 of the Litellm package, available on the Python Package Index (PyPI), were reported as compromised. This supply chain attack potentially affects thousands of users who may have updated to the malicious versions. The compromised packages could contain malicious code injected by an unknown threat actor. Users are advised to avoid updating to these versions and investigate their systems for potential compromise. The initial report came from a Reddit post and links to a blog post for further details.

## Attack Chain

While the specifics of the attack chain are not fully detailed in the source, a typical supply chain attack targeting PyPI packages involves the following steps:

1. **Package Compromise:** Threat actor gains unauthorized access to the Litellm PyPI account or the build environment.
2. **Malicious Code Injection:** The attacker injects malicious code into the setup.py or other relevant files within the Litellm package. This malicious code could be designed to execute upon installation.
3. **Version Release:** The compromised versions, 1.82.7 and 1.82.8, are released to PyPI, making them available for users to download and install.
4. **Package Installation:** Users unknowingly download and install the compromised Litellm package using pip, triggering the execution of the injected malicious code.
5. **Initial Access:** The malicious code may establish a reverse shell, download additional payloads, or perform other actions to gain initial access to the victim's system.
6. **Persistence:** The attacker may establish persistence on the compromised system through various techniques, such as creating scheduled tasks or modifying startup scripts.
7. **Data Exfiltration/Malware Deployment:** Depending on the attacker's objective, they may exfiltrate sensitive data, deploy ransomware, or perform other malicious activities.
8. **Lateral Movement:** The attacker may attempt to move laterally to other systems within the compromised network, escalating their access and expanding their reach.

## Impact

The compromise of Litellm versions 1.82.7 and 1.82.8 could lead to widespread compromise of systems that use the package. The injected malicious code could enable attackers to steal sensitive information, deploy malware, or gain unauthorized access to victim systems. The number of affected users is estimated to be in the thousands. This incident highlights the risks associated with supply chain attacks targeting open-source software repositories.

## Recommendation

*   Immediately stop updating to Litellm versions 1.82.7 and 1.82.8.
*   Revert to a known-good version of Litellm prior to 1.82.7.
*   Analyze network connections for suspicious traffic originating from systems where the compromised Litellm versions were installed, using network connection logs.
*   Monitor process creations for suspicious processes spawned from Python executables where Litellm is installed, using process creation logs and the Sigma rules provided below.
*   Investigate systems where Litellm 1.82.7 or 1.82.8 were installed for any signs of compromise.
*   Review the blog post at https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/ for further details on the compromise.
