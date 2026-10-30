---
brief_id: brief-2026-10-30-nx-maven-gradle-rce
event_id: brief-2026-10-30-nx-maven-gradle-rce
revision: 1
activity_at: "2026-10-30T15:10:15Z"
title: 'Nx Maven and Gradle plugins: OS command injection (CVE-2026-119282)'
slug: 2026-10-nx-maven-gradle-rce
description: The @nx/maven and @nx/gradle plugins contain an OS command injection vulnerability where unsafely interpolated nx.json configuration options lead to arbitrary command execution during project-graph analysis.
date: "2026-10-30T15:10:15Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source documentation fully reviewed; vendor-provided fixed versions included.
tags:
  - supply-chain
  - command-injection
  - nodejs
vendors:
  - Nx
products:
  - '@nx/maven (>= 22.0.2, < 22.7.9; >= 23.0.0, < 23.1.2)'
  - '@nx/gradle (>= 21.0.0, < 22.7.9; >= 23.0.0, < 23.1.2)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Both plugins spawn their analyzer through a shell and interpolate nx.json plugin options into the command, so those option values are shell source.
    confidence_band: high
cves:
  - id: CVE-2026-119282
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-qm8w-vx34-5j9j
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119282
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Upgrade affected Nx workspaces to @nx/maven or @nx/gradle versions 22.7.9 or 23.1.2
      owner: Development Teams
      due: 48h
      evidence: Remediation section of GHSA-qm8w-vx34-5j9j
  hunt_leads:
    - lead: Identify CI/CD pipelines or local developer environments executing nx commands on external or untrusted repositories.
      technique_id: T1059.004
      data_needed:
        - CI/CD execution logs
        - Repository manifest analysis
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A victim who runs an ordinary nx command in an attacker-supplied Maven or Gradle workspace gets code execution as themselves.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict trust policies for code execution in CI/CD, specifically avoiding automatic execution of 'nx' commands on unverified pull requests.
      owner: DevOps
      addresses: CVE-2026-119282
      evidence: If you cannot upgrade yet, only run nx commands in repositories you trust.
---

The Nx plugins `@nx/maven` and `@nx/gradle` are susceptible to OS command injection due to insecure interpolation of plugin options from `nx.json` into shell commands. This vulnerability is triggered whenever an `nx` command initiates project-graph analysis in a workspace containing a maliciously crafted `nx.json`.

For `@nx/maven`, the injectable option is `targetNamePrefix`. For `@nx/gradle`, the vulnerability is more extensive, as arbitrary plugin option names and values are interpolated into command-line arguments. This flaw poses a risk to CI environments and local developers working within untrusted repositories. There is no evidence of active exploitation in the wild.

## Impact

Successful exploitation allows arbitrary command execution under the privileges of the user running the `nx` command. This represents a significant risk in automated CI pipelines that process pull requests or external repositories, as an attacker with write access to the `nx.json` file can execute code without requiring access to build files themselves.

## Recommendation

* Upgrade `@nx/maven` and `@nx/gradle` to version **22.7.9** (for the 22.x line) or **23.1.2** (for the 23.x line) or later.
* Upgrading the plugin alone is insufficient; users must ensure the core `nx` package is also upgraded to a compatible version as the fix depends on updated core code.
* Use `nx migrate 23.1.2` to update the project dependencies.
* Until updates are applied, restrict the execution of `nx` commands to repositories from trusted sources only.
