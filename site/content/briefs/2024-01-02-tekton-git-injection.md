---
title: Tekton Pipeline Git Resolver Git Argument Injection Vulnerability
slug: 2024-01-02-tekton-git-injection
description: The Tekton Pipeline Git Resolver is vulnerable to git argument injection due to the unsanitized `revision` parameter in the `git fetch` command, allowing remote code execution on the resolver pod and cluster-wide secret exfiltration.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - tekton
  - git
  - injection
  - rce
  - secret-exfiltration
  - kubernetes
vendors:
  - Tekton
products:
  - Tekton Pipelines
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/advisories/GHSA-94jr-7pqp-xhcq
rules:
  - title: Detect Tekton Git Resolver Upload Pack Injection
    description: Detects process creations that use the `--upload-pack` argument, indicating a potential git argument injection vulnerability in the Tekton Git Resolver.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Tekton Git Resolver Local Path Access
    description: Detects process creations where git is used with a local file path as the repository URL, potentially indicating exploitation of the local path vulnerability in Tekton Git Resolver.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Tekton Pipeline Git Resolver is susceptible to a git argument injection vulnerability. This flaw stems from the improper sanitization of the `revision` parameter, which is directly passed to the `git fetch` command. This allows an attacker to inject arbitrary `git fetch` flags, such as `--upload-pack=<binary>`. Coupled with the ability to specify local filesystem paths as Git repositories, this enables a malicious actor to execute arbitrary binaries on the resolver pod. The vulnerability affects Tekton Pipelines versions 1.0.0 through 1.11.0. Successful exploitation leads to full cluster-wide secret exfiltration due to the resolver pod's ServiceAccount permissions. This vulnerability impacts any Tekton Pipeline installation where untrusted users can submit ResolutionRequest objects.

## Attack Chain

1.  An attacker crafts a `ResolutionRequest` object with a malicious `revision` parameter. This parameter contains a `git fetch` flag such as `--upload-pack=/usr/bin/curl`. The `url` parameter is set to a local file system path.
2.  The Tekton Git Resolver receives the `ResolutionRequest` and calls the `checkout` function in `pkg/resolution/resolver/git/repository.go`.
3.  The `checkout` function executes `git fetch origin <malicious revision> --depth=1` via `exec.CommandContext`, without any validation on the revision parameter.
4.  Git interprets the injected `--upload-pack` flag and executes the specified binary (e.g., `/usr/bin/curl`) on the resolver pod.  The path to a git repository is passed to the executed command as an argument.
5.  The attacker uses the executed binary (e.g. curl) to exfiltrate sensitive information, such as the service account token found at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
6.  The attacker uses the service account token to read secrets from the Kubernetes API, since the `tekton-pipelines-resolvers` ServiceAccount has cluster-wide `get/list/watch` permissions on all Secrets.
7.  The attacker escalates privileges by using the exfiltrated secrets, such as kubeconfig files or cloud provider credentials, to move laterally within the cloud infrastructure.

## Impact

This vulnerability allows for arbitrary code execution on the Tekton Pipeline resolver pod. Since the `tekton-pipelines-resolvers` ServiceAccount possesses cluster-wide `get/list/watch` permissions on all Secrets, successful exploitation leads to full cluster-wide Secret exfiltration. This can then be leveraged for privilege escalation and lateral movement within the associated cloud infrastructure. The impact is significant, potentially leading to complete compromise of the Kubernetes cluster and associated resources. This issue affects Tekton Pipelines installations with versions ranging from 1.0.0 to 1.11.0.

## Recommendation

*   Deploy the Sigma rule `Detect Tekton Git Resolver Upload Pack Injection` to detect exploitation attempts by monitoring process creations with the `--upload-pack` argument.
*   Apply Fix 1 as described in the advisory by validating that the `revision` parameter does not begin with a `-` character in `PopulateDefaultParams`.
*   Apply Fix 2 by restricting `validateRepoURL` to remote URLs only to eliminate local-path remotes.
*   Upgrade Tekton Pipelines to a patched version beyond 1.11.0 to remediate CVE-2026-40938.
