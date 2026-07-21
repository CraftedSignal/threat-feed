---
title: OS Command Injection in AWS CDK NodejsFunction Docker Bundling (CVE-2026-13760)
slug: 2026-07-os-command-injection-aws-cdk-lib
description: An OS command injection vulnerability, CVE-2026-13760, in AWS CDK's `aws-cdk-lib` package before version 2.260.0 allows an attacker to execute arbitrary commands on the host running the CDK toolchain by injecting shell metacharacters into dependency version strings within a project's `package.json` file when using Docker-based NodejsFunction bundling.
date: "2026-07-21T19:09:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - supply-chain
  - cloud-native
  - aws-cdk
  - vulnerability
vendors:
  - AWS
products:
  - aws-cdk-lib
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: values containing shell metacharacters could execute arbitrary commands inside the bundling container
    confidence_band: high
cves:
  - id: CVE-2026-13760
    cvss: 7.3
    epss: 0.0061
references:
  - https://github.com/advisories/GHSA-vcrf-j523-4mrf
---

A high-severity OS command injection vulnerability, CVE-2026-13760, has been identified in the `aws-cdk-lib` package of the AWS Cloud Development Kit (CDK) framework, affecting versions prior to 2.260.0. This flaw allows an actor to execute arbitrary commands on the host system running the CDK toolchain if they can control dependency version strings in a project's `package.json` file. The vulnerability specifically impacts Docker-based Lambda bundling when the `nodeModules` option is specified. During this process, `NodejsFunction` constructs a shell command string using module version strings without proper sanitization. An attacker can leverage this by embedding shell metacharacters in a controlled version string, leading to command execution within the bundling container. Since the container has read/write bind mounts to the host filesystem, this effectively grants the attacker arbitrary code execution on the host with the privileges of the user executing `cdk synth`, `cdk deploy`, or `cdk diff`.

## Attack Chain

1. An attacker gains control over dependency version strings in a project's `package.json` file, potentially via a compromised or untrusted npm package referenced through `nodeModules`.
2. The attacker inserts shell metacharacters (e.g., `;`, `|`, `&&`) into one of the controlled dependency version strings.
3. A developer or CI/CD pipeline uses `aws-cdk-lib` with `NodejsFunction` and Docker-based bundling, with the `nodeModules` option specified, to deploy their cloud infrastructure.
4. During the bundling process, the CDK toolchain processes the `package.json` file to assemble a shell command string for operations inside the Docker container.
5. The `NodejsFunction`'s internal `OsCommand` helper interpolates the malicious dependency version string into the shell command without proper escaping.
6. The bundling container executes the crafted shell command via `bash -c`, which interprets the injected shell metacharacters as distinct commands.
7. Arbitrary commands specified by the attacker are executed within the bundling container, leveraging its access to the host filesystem via read/write bind mounts.
8. The injected commands execute on the host machine, typically with the privileges of the user who initiated the `cdk synth`, `cdk deploy`, or `cdk diff` command.

## Impact

Successful exploitation of CVE-2026-13760 allows an attacker to achieve arbitrary code execution on the developer's workstation or CI/CD environment where the AWS CDK toolchain is executed. This can lead to complete compromise of the build environment, exfiltration of sensitive source code, AWS credentials, or other intellectual property. The attacker gains the privileges of the user running the `cdk` commands, which can often be elevated, posing a significant supply chain risk. While no specific victim counts or sectors are mentioned, any organization using `aws-cdk-lib` with Docker-based bundling and susceptible to untrusted `package.json` dependency version string manipulation is at risk.

## Recommendation

* Upgrade `aws-cdk-lib` to version 2.260.0 or later immediately to patch CVE-2026-13760.
* Audit all third-party constructs and dependencies in your `package.json` to ensure the modules listed in the `nodeModules` bundling option and their version strings come only from trusted sources.
* Consider using local bundling instead of Docker-based bundling for `NodejsFunction` where feasible, as this bypasses the affected code path.
* Ensure that any forked or derivative codebases incorporating `aws-cdk-lib` are also updated to address CVE-2026-13760.
