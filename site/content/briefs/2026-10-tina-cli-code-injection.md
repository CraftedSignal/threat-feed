---
title: TinaCMS CLI Arbitrary Code Execution via Git Branch Name Injection
slug: 2026-10-tina-cli-code-injection
description: The TinaCMS CLI package fails to sanitize Git branch names during client code generation, allowing an attacker to inject and execute arbitrary JavaScript expressions within consumer build environments.
date: "2026-10-09T21:24:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tinacms:cli:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - code-injection
  - ci-cd
  - rce
vendors:
  - TinaCMS
products:
  - TinaCMS CLI (<= 2.7.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The injected expression executes with the full privileges of the consumer build process.
    confidence_band: high
cves:
  - id: CVE-2026-108259
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-pwhx-cvv3-qj5c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108259
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security
  immediate_actions:
    - action: Upgrade TinaCMS CLI to 3.0.0 or later
      owner: DevOps
      due: 48h
      evidence: Source advises upgrading to mitigate CVE-2026-108259
  mitigation_plan:
    - priority: immediate
      action: Upgrade TinaCMS CLI to 3.0.0 or later
      owner: DevOps
      addresses: CVE-2026-108259
      evidence: Source advisory recommending package update
---

The TinaCMS CLI (up to version 2.7.0) contains a code injection vulnerability arising from the unsafe handling of Git branch names during the generation of client source code. The package reads environment variables like `VERCEL_GIT_COMMIT_REF` or `GITHUB_BRANCH` and incorporates the raw string into the generated `client.ts` file without any sanitization or encoding. Because the resulting string is placed inside a single-quoted JavaScript template, an attacker can use a Git branch name containing single quotes and JavaScript syntax to escape the string literal and execute arbitrary code. This execution occurs during the build process of consumer projects, such as preview deployments in CI/CD pipelines, granting the attacker access to build-time environment variables, credentials, and the ability to modify build artifacts.

## Attack Chain

1. Attacker identifies a target repository using an affected version of `tinacms/cli` for their build pipeline.
2. Attacker initiates a pull request or creates a branch in the target repository.
3. Attacker names the Git branch with a malicious payload (e.g., `x'+(globalThis.__TINA_PROBE='hit')+'`).
4. The victim's CI/CD platform (e.g., Vercel, GitHub Actions) triggers an automated build for the new branch.
5. The TinaCMS CLI codegen process reads the malicious branch name from the environment.
6. The CLI concatenates the payload into the `client.ts` template and writes it to the local file system.
7. The CI build process runs a bundler (e.g., esbuild) which parses and evaluates the injected JavaScript code.
8. The injected expression executes within the build environment, potentially leaking secrets or altering the final deployment artifact.

## Impact

Successful exploitation results in arbitrary code execution within the build environment. This poses a significant risk to CI/CD pipelines by potentially exposing `NPM_TOKEN`, `VERCEL_TOKEN`, cloud API keys, and other build-time secrets. Furthermore, attackers can modify build artifacts to inject malicious code into the final production output, leading to downstream supply-chain compromises for users of the deployed application.

## Recommendation

1. Upgrade `@tinacms/cli` to a version that properly sanitizes branch input or migrates runtime configuration to JSON files as recommended by the vendor.
2. Audit CI/CD logs for build-time errors occurring during the codegen phase, as malformed branch names may cause unexpected build failures.
3. Review CI/CD environment configurations to minimize the exposure of sensitive tokens and secrets during preview deployments, which are most vulnerable to this attack vector.
4. Patch CVE-2026-108259 immediately by updating the affected `@tinacms/cli` package in `package.json`.
