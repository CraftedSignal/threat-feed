---
title: Unauthenticated Access to backpropagate UI via Authentication Bypass (CVE-2026-48797)
slug: 2026-07-backpropagate-auth-bypass
description: An authentication bypass vulnerability in `backpropagate` versions >= 1.1.0 and < 1.2.0 allows unauthenticated attackers to gain full control over the Reflex web UI, even when HTTP Basic authentication is ostensibly enabled via the `--auth` flag, permitting data exfiltration, arbitrary training runs, HuggingFace Hub push, disk-fill DoS, and sensitive path discovery.
date: "2026-07-03T10:32:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - critical-vulnerability
  - supply-chain
  - data-exfiltration
  - denial-of-service
  - web-ui
  - machine-learning
  - reflex
vendors:
  - mcp-tool-shop-org
products:
  - backpropagate (>= 1.1.0, < 1.2.0)
  - '@mcptoolshop/backpropagate (>= 1.1.0, < 1.2.0)'
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who reaches the bound port can ... access the UI without authentication due to the bypass.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Trigger arbitrary training runs against any base model the operator has installed locally or that can be downloaded from HuggingFace.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Read model paths (`source_model_path`, `dataset_path`, `model`, `uploaded_path`) which are user-supplied and bypass the `safe_path()` helper
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Read uploaded datasets rendered in the UI preview, including content of any JSONL/CSV/TXT file the legitimate operator has uploaded
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Read uploaded datasets rendered in the UI preview, including content of any JSONL/CSV/TXT file the legitimate operator has uploaded for fine-tuning.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Trigger HuggingFace Hub pushes to repositories named via the UI input (subject to the operator's local HF token's scope)
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Cause disk-fill DoS via the `rx.upload` endpoint (no size cap, no extension filter, no per-session count cap in v1.1.0 / v1.1.1).
    confidence_band: high
cves:
  - id: CVE-2026-48797
    epss: 0.00324
references:
  - https://github.com/advisories/GHSA-f65r-h4g3-3h9h
  - https://github.com/mcp-tool-shop-org/backpropagate/blob/main/CHANGELOG.md#120---2026-05-23
iocs:
  - type: url
    value: https://github.com/mcp-tool-shop-org/backpropagate/blob/main/CHANGELOG.md#120---2026-05-23
  - type: domain
    value: github.com
  - type: domain
    value: huggingface.co
ioc_counts:
  domain: 2
  url: 1
---

A critical authentication bypass vulnerability, tracked as CVE-2026-48797, exists in the `backpropagate` machine learning operations tool (versions >= 1.1.0 and < 1.2.0), specifically affecting its optional Reflex web UI. Despite documented command-line flags `--auth user:pass` and `--share` intended to enforce HTTP Basic authentication and control public exposure, the Reflex backend fails to implement any authentication middleware. This oversight means any attacker able to reach the UI's bound port, whether locally or remotely, gains full administrative control without credentials. This flaw enables attackers to read sensitive uploaded datasets, initiate arbitrary model training, push tampered models to HuggingFace Hub accounts, and trigger denial-of-service through uncontrolled file uploads, posing significant data exfiltration and supply-chain compromise risks. The vulnerability was discovered by an internal audit on May 22, 2026, and patched in version 1.2.0.

## Attack Chain

1.  **Reconnaissance & Initial Access**: An attacker identifies a running `backpropagate` Reflex UI instance (version >= 1.1.0, < 1.2.0) bound to a network accessible port. This may be `localhost` (default) or a public address if the legitimate operator used the `--share` flag.
2.  **Authentication Bypass**: The attacker accesses the UI's HTTP endpoint without providing any credentials, as the documented `--auth` flag does not enforce authentication.
3.  **Information Disclosure**: The attacker navigates the UI to view uploaded datasets (e.g., JSONL/CSV/TXT files) and extracts sensitive information used for fine-tuning.
4.  **Discovery**: The attacker can read `source_model_path`, `dataset_path`, `model`, and `uploaded_path` values from the UI, bypassing `safe_path()` helpers and potentially revealing internal file system structure.
5.  **Arbitrary Execution**: The attacker triggers arbitrary training runs against any locally installed base model or models downloadable from HuggingFace, potentially leading to remote code execution or resource exhaustion.
6.  **Supply Chain Compromise**: The attacker initiates HuggingFace Hub pushes to repositories specified via the UI, potentially pushing malicious or tampered model weights to the operator's account.
7.  **Denial of Service**: The attacker exploits the `rx.upload` endpoint, which lacks size, extension, or count caps, to upload large files and exhaust disk space, causing a denial of service.

## Impact

This critical vulnerability enables a range of severe consequences. Attackers can exfiltrate sensitive uploaded datasets, such as proprietary training data, client information, or other confidential records. They can also initiate arbitrary model training, potentially leading to resource abuse or arbitrary code execution within the victim's environment. The ability to trigger HuggingFace Hub pushes poses a significant supply-chain risk, allowing attackers to inject malicious or tampered models into the victim's publicly hosted repositories. Furthermore, uncontrolled file uploads via the `rx.upload` endpoint can lead to disk-fill denial-of-service attacks, disrupting critical ML operations. The impact extends to all users running vulnerable versions of `backpropagate` who either expose the UI publicly or have local attackers.

## Recommendation

*   Immediately upgrade `backpropagate` to version 1.2.0 or higher by running `pip install --upgrade backpropagate` to patch CVE-2026-48797.
*   If immediate upgrade is not possible, do NOT use the `--auth` or `--share` flags with `backprop ui` as they are ineffective.
*   For remote access, use SSH port-forwarding (as described in the brief) to secure access to the `backpropagate` UI, leveraging SSH's authentication mechanisms.
*   Audit existing `backpropagate` deployments for any instances launched with `--share` prior to May 23, 2026, as these instances were openly accessible.
*   Re-issue HuggingFace API tokens that were in use on systems running vulnerable `backpropagate` UI instances exposed with `--share` due to potential compromise of push targets.
*   Review webserver access logs for the `backpropagate` UI for suspicious unauthenticated access to sensitive endpoints like `/rx.upload` or data preview pages if proxying the UI through a webserver.
