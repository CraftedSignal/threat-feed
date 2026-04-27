---
title: Malicious LiteLLM Versions Harvest Credentials
slug: 2026-03-litellm-supply-chain
description: Compromised versions of the LiteLLM package (1.82.7 and 1.82.8) on PyPI contained malware designed to harvest sensitive credentials and files, exfiltrating them to a remote API, impacting users who installed and ran the package.
date: "2026-03-26T12:00:00Z"
severities:
  - critical
tags:
  - supply-chain
  - malware
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-5mg7-485q-xm76
  - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack
  - https://github.com/pypa/advisory-database/tree/main/vulns/litellm/PYSEC-2026-2.yaml
  - https://inspector.pypi.io/project/litellm/1.82.7/packages/79/5f/b6998d42c6ccd32d36e12661f2734602e72a576d52a51f4245aef0b20b4d/litellm-1.82.7-py3-none-any.whl/litellm/proxy/proxy_server.py#line.130
  - https://inspector.pypi.io/project/litellm/1.82.8/packages/f6/2c/731b614e6cee0bca1e010a36fd381fba69ee836fe3cb6753ba23ef2b9601/litellm-1.82.8.tar.gz/litellm-1.82.8/litellm_init.pth#line.1
  - https://www.wiz.io/blog/teampcp-attack-kics-github-action
rules:
  - title: Detect Installation of Malicious LiteLLM Versions
    description: Detects the installation of compromised LiteLLM packages versions 1.82.7 and 1.82.8 via pip
    platform: sigma
    severity: critical
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
  - title: Suspicious File Creation in LiteLLM Package Directory
    description: Detects suspicious file creation events within the litellm package installation directory, potentially indicating malware activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 25, 2026, two malicious versions of the `litellm` package (versions 1.82.7 and 1.82.8) were discovered on the PyPI repository. These versions were found to contain automatically activated malware. The malicious code was designed to harvest sensitive credentials and files from systems where the compromised packages were installed. This supply chain attack follows a previous API token exposure stemming from a compromised trivy dependency, indicating a potential escalation in targeting…
