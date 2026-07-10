---
title: TeamPCP Targets LiteLLM Package on PyPI
slug: 2024-03-teampcp-litellm
description: TeamPCP, the threat actor behind previous compromises of Trivy and KICS, has now targeted LiteLLM, a popular Python package on PyPI with 95 million monthly downloads.
date: "2024-03-25T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - pypi
  - teampcp
  - litellm
vendors:
  - LiteLLM
products:
  - LiteLLM
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s2nupn/teampcp_isnt_done_threat_actor_behind_trivy_and/
  - https://www.endorlabs.com/learn/teampcp-isnt-done
rules:
  - title: Suspicious Outbound Connection from Python Executable
    description: Detects suspicious outbound network connections initiated by Python executables, potentially indicating a compromised package exfiltrating data.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Package Install from Unusual Source
    description: Detects package installation from a location other than the default PyPI repository, suggesting a potentially malicious custom repository.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The threat actor known as TeamPCP, previously linked to the compromise of Trivy and KICS, has now set its sights on LiteLLM, a high-profile package available on the Python Package Index (PyPI). LiteLLM boasts an impressive 95 million monthly downloads, making it a significant target for malicious actors. This incident highlights the ongoing risk supply chain attacks pose to software developers and users. By compromising widely used packages, attackers can potentially inject malicious code into numerous projects, leading to widespread security breaches and data compromise. Defenders should prioritize monitoring their software supply chains and implement robust security measures to mitigate the risk of such attacks.

## Attack Chain

1.  **Compromise PyPI Account:** TeamPCP gains unauthorized access to the PyPI account of a LiteLLM maintainer, potentially through credential theft or social engineering.
2.  **Inject Malicious Code:** The attacker injects malicious code into a new or existing version of the LiteLLM package. This code is designed to be stealthy and blend in with the legitimate codebase.
3.  **Publish Malicious Package:** The compromised account is used to publish the malicious version of LiteLLM to PyPI, making it available for download by unsuspecting users.
4.  **Package Download:** Developers using LiteLLM automatically download the malicious version as part of their dependency management process (e.g., using pip).
5.  **Malicious Code Execution:** When developers install the compromised package, the malicious code is executed within their development environment or deployed applications.
6.  **Data Exfiltration/Backdoor:** The malicious code may perform various actions, such as exfiltrating sensitive data (API keys, credentials, environment variables) or establishing a backdoor for remote access.
7.  **Lateral Movement (Optional):** If the compromised environment has access to other systems or networks, the attacker may attempt to move laterally and compromise additional targets.

## Impact

The compromise of LiteLLM, with its 95 million monthly downloads, represents a significant supply chain risk. Successful exploitation could lead to the widespread compromise of developer environments and applications that rely on the package. This could result in data breaches, unauthorized access to sensitive systems, and reputational damage for both LiteLLM users and the LiteLLM project itself. The scale of the potential impact is substantial, given the widespread adoption of the package.

## Recommendation

*   Implement software composition analysis (SCA) tools to detect malicious or vulnerable dependencies in your projects.
*   Monitor your Python package installations for unexpected network connections or file modifications, which may indicate a compromised package (see example Sigma rule below for network connection monitoring).
*   Enforce multi-factor authentication (MFA) for all PyPI accounts and other critical infrastructure to prevent unauthorized access.
*   Implement integrity checks for downloaded packages to ensure they have not been tampered with.
