---
title: Red Hat Cloud Services npm Packages Hijacked
slug: 2026-06-redhat-npm-hijack
description: Multiple npm packages within the legitimate @redhat-cloud-services namespace have been hijacked with malicious code, posing a supply chain risk.
date: "2026-06-01T22:26:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - npm
  - supply-chain
  - package-hijacking
vendors:
  - Red Hat
products:
  - '@redhat-cloud-services namespace'
references:
  - https://www.sonatype.com/blog/red-hat-cloud-services-npm-packages-hijacked
  - https://guide.sonatype.com/vulnerability/sonatype-2026-003508/components-impacted
rules:
  - title: Detect Suspicious npm Package Installation from @redhat-cloud-services
    description: Detects installation of npm packages from the @redhat-cloud-services namespace, which may indicate a supply chain attack.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation After npm Install
    description: Detects suspicious file creation events shortly after an npm install command is executed, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A new wave of malicious activity has been reported targeting the npm ecosystem. This incident involves the hijacking of multiple packages within the legitimate `@redhat-cloud-services` namespace. While the specifics of the malicious code's functionality are not detailed in this brief, the compromise of a trusted namespace poses a significant supply chain risk. Developers and organizations using these packages may unknowingly introduce malicious code into their projects, potentially leading to data theft, system compromise, or other malicious activities. This incident underscores the importance of supply chain security and the need for robust package verification mechanisms.

## Attack Chain

1.  Attacker gains unauthorized access to the npm account or credentials associated with the `@redhat-cloud-services` namespace.
2.  Compromised account is used to publish malicious versions of existing packages within the namespace.
3.  Developers unknowingly install the compromised packages as dependencies in their projects using `npm install`.
4.  The malicious code within the hijacked package is executed during the build or runtime of the application.
5.  Malicious code performs an action, such as exfiltrating environment variables or other sensitive data.
6.  Data is sent to attacker-controlled infrastructure.

## Impact

The hijacking of npm packages within the `@redhat-cloud-services` namespace can have significant consequences. Developers and organizations that rely on these packages may unknowingly introduce malicious code into their projects. This can lead to data theft, system compromise, or other malicious activities. The scope of the impact depends on the popularity and usage of the compromised packages.

## Recommendation

*   Monitor npm package installations for unexpected versions or changes in dependencies, especially within the `@redhat-cloud-services` namespace (see rules below).
*   Implement software composition analysis (SCA) tools to detect known vulnerabilities and malicious code in npm packages.
*   Enable logging of npm package installations and usage to facilitate incident investigation.
*   Regularly audit npm dependencies to identify and remove any suspicious or unnecessary packages.
