---
title: Arbitrary Code Execution in AWS Amplify Studio via Input Validation Flaw
slug: 2026-07-amplify-codegen-ui-rce
description: The amplify-codegen-ui package is vulnerable to arbitrary code execution due to insufficient input validation during the component expression-binding process, allowing authenticated users to inject malicious JavaScript.
date: "2026-07-30T21:29:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - rce
  - amplify
vendors:
  - Amazon
products:
  - amplify-codegen-ui (2.20.2)
  - '@aws-amplify/codegen-ui-react (2.20.2)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The expression-binding function does not validate the component schema properties before converting them to expressions, allowing arbitrary JavaScript code execution.
    confidence_band: high
cves:
  - id: CVE-2025-4318
    epss: 0.00923
references:
  - https://github.com/advisories/GHSA-hf3j-86p7-mfw8
  - https://github.com/aws-amplify/amplify-codegen-ui/pull/1174
  - https://github.com/aws-amplify/amplify-codegen-ui/pull/1196
  - https://github.com/aws-amplify/amplify-codegen-ui/releases/tag/v2.20.4
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/amplifyuibuilder/create-component.html
---

The AWS Amplify Studio `amplify-codegen-ui` package contains a critical input validation vulnerability, tracked as CVE-2025-4318, affecting versions 2.20.2 and earlier. This package is responsible for generating front-end code from UI Builder entities. The vulnerability resides in the expression-binding function, which fails to adequately validate component schema properties before processing them. 

An authenticated attacker who can manipulate component schemas via the AWS Amplify Studio interface or the `create-component` CLI command can inject arbitrary JavaScript expressions. These expressions are executed during the component rendering and build phases. Because these processes often run in the context of the user's build environment or automated CI/CD pipelines, this flaw could lead to unauthorized code execution, potential exfiltration of environment secrets, or further compromise of the development infrastructure. Users are advised to upgrade to version 2.20.4 or later to remediate this issue.

## Impact

Successful exploitation allows for arbitrary code execution within the build environment of applications utilizing AWS Amplify Studio. This could lead to a compromise of CI/CD pipeline integrity, unauthorized access to build-time secrets, or the injection of malicious code into the final application frontend. The vulnerability impacts any organization using `amplify-codegen-ui` versions <= 2.20.2 for generating component files.

## Recommendation

- Upgrade `amplify-codegen-ui` and `@aws-amplify/codegen-ui-react` packages to version 2.20.4 or higher immediately to address CVE-2025-4318.
- Audit CI/CD pipelines and AWS Amplify Studio component schemas for unauthorized modifications or suspicious expression patterns introduced by unexpected users.
- Review access control policies for AWS Amplify Studio to restrict component creation and modification capabilities to verified administrators.
