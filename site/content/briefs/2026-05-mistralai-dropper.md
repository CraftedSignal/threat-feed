---
title: Malicious Dropper Found in mistralai PyPI Package 2.4.6
slug: 2026-05-mistralai-dropper
description: The mistralai PyPI package version 2.4.6 contains a malicious dropper that executes on import on Linux, downloading and executing a second-stage payload from a remote IP address, potentially leading to arbitrary code execution.
date: "2026-05-18T17:56:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - malware
  - python
vendors:
  - Mistral AI
products:
  - mistralai client-python
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-wx9m-wx4f-4cmg
  - https://github.com/mistralai/client-python/issues/523
  - https://pypi.org/project/mistralai/
iocs:
  - type: ip
    value: 83.142.209.194
  - type: url
    value: https://83.142.209.194/transformers.pyz
  - type: hash_sha256
    value: 6dbaa43bf2f3c0d3cddbca74967e952da563fb974c1ef9d4ecbb2e58e41fe81b
ioc_counts:
  hash_sha256: 1
  ip: 1
  url: 1
rules:
  - title: Detect Malicious mistralai Package - Suspicious Curl Download
    description: Detects suspicious curl command downloading a file from a known malicious IP address related to the malicious mistralai package.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious mistralai Package - Python Executing Downloaded File
    description: Detects a Python interpreter executing the downloaded transformers.pyz file from /tmp, indicating potential second-stage execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `mistralai` PyPI package version `2.4.6` contains a malicious dropper that executes upon import on Linux systems. This malicious version was uploaded without a corresponding tag, commit, or release workflow run in the legitimate repository, and it bypassed the normal release pipeline that uses PyPI Trusted Publishing. The legitimate latest version before the malicious upload was `2.4.5`. Upon import, the package attempts to download and execute a file from a remote server. The `mistralai` PyPI project has been quarantined as a result. This incident highlights the risk of supply chain attacks targeting software dependencies and the importance of verifying package integrity. Defenders should monitor for unexpected network connections and file creations originating from Python interpreters.

## Attack Chain

1. A malicious version 2.4.6 of the `mistralai` package is uploaded to PyPI.
2. A user installs the malicious package using `pip install mistralai==2.4.6`.
3. The user imports the `mistralai` package in a Python script (e.g., `import mistralai`).
4. The `_run_background_task` function in `src/mistralai/client/__init__.py` executes.
5. The function checks if the operating system is Linux and if the `MISTRAL_INIT` environment variable is set. If not, it proceeds.
6. The function attempts to download `https://83.142.209.194/transformers.pyz` to `/tmp/transformers.pyz` using `curl -k -L -s`.
7. If the download is successful, the function executes `/tmp/transformers.pyz` using the current Python interpreter via `_sub.Popen`, discarding stdout and stderr.
8. The second-stage payload in `transformers.pyz` executes, with the nature of its actions unknown, potentially leading to arbitrary code execution and system compromise.

## Impact

Successful execution of the dropper leads to the download and execution of an unknown second-stage payload on Linux systems. The impact is potentially severe, as the attacker could gain unauthorized access to the compromised system, exfiltrate sensitive data, install malware, or perform other malicious activities. Given the popularity of machine learning libraries, a successful attack could affect a wide range of users and organizations. Any Linux environment that imported `mistralai==2.4.6` should be treated as potentially compromised.

## Recommendation

*   Immediately pin `mistralai` to version `2.4.5` or earlier to prevent further installations of the malicious package.
*   Rotate every credential reachable from any process that imported `mistralai==2.4.6` as described in the advisory.
*   Review host and cloud audit logs for activity from approximately 2026-05-12 00:05 UTC onward, per the advisory.
*   Monitor for outbound HTTPS connections to `83.142.209.194` originating from `curl` processes, as outlined in the IOCs.
*   Implement a detection rule to identify the execution of `/tmp/transformers.pyz` by a Python interpreter, based on the process execution information provided in the attack chain.
*   Block the domain `83.142.209.194` at the firewall or DNS resolver based on the IOCs.
