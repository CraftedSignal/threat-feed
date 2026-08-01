---
title: Environment Variable Exfiltration in GitPython
slug: 2026-08-gitpython-exfiltration
description: GitPython versions prior to 3.1.52 are vulnerable to environment variable exfiltration when an attacker provides a crafted remote URL to the Repo.clone_from() method.
date: "2026-08-01T13:52:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - library-vulnerability
  - credential-theft
vendors:
  - GitPython
products:
  - GitPython (< 3.1.52)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: The resulting URL, now containing the secret, is transmitted over the network to an attacker-controlled host during the clone attempt, disclosing the secret.
    confidence_band: high
cves:
  - id: CVE-2026-67322
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67322
---

GitPython versions before 3.1.52 contain a critical vulnerability in the `Repo.clone_from()` method, which improperly handles remote URL inputs. On non-Cygwin platforms, the library uses `os.path.expandvars()` on the provided URL string before executing the underlying `git clone` command. This behavior allows an attacker capable of influencing the remote URL argument to inject shell-style environment variable tokens, such as `$AWS_SECRET_ACCESS_KEY` or `$GITHUB_TOKEN`. When `Repo.clone_from()` is called, the library resolves these tokens to the actual values present in the hosting process's environment. The process then attempts to connect to a remote host specified in the crafted URL, effectively leaking the environment variable value to an attacker-controlled server. This vulnerability poses a significant risk to CI/CD pipelines, automated build systems, and any application that uses GitPython to interact with user-provided or untrusted repository URLs.

## Impact

The vulnerability allows for the unauthorized exfiltration of sensitive environment variables, including credentials, API keys, and tokens stored in the memory space of the process utilizing GitPython. Successful exploitation can lead to a complete compromise of cloud service accounts, source code repositories, and other integrated systems relying on environment-based authentication. The scope of impact is dependent on the sensitivity of the variables present in the environment where the affected GitPython library is executing.

## Recommendation

* Update GitPython to version 3.1.52 or later immediately to patch the vulnerable `Repo.clone_from()` implementation.
* Audit applications utilizing GitPython to determine if repository URLs are derived from user input or external, untrusted sources.
* Implement strict allowlisting for repository URLs in applications that must clone external repositories, ensuring they point only to trusted, expected domains.
* Rotate any credentials or tokens that may have been exposed in environment variables if the application environment was potentially reachable by untrusted inputs during the period of vulnerability.
