---
title: AWS API MCP Server Security Policy Bypass via Startup Initialization Failure (CVE-2026-16584)
slug: 2026-07-aws-mcp-policy-bypass
description: The AWS API MCP Server has a high-severity vulnerability, CVE-2026-16584, where a failure to initialize security policy data at server startup leads to a silent bypass of all per-request policy checks, allowing AWS API operations to execute without the intended restrictions, though underlying IAM permissions remain enforced.
date: "2026-07-24T22:40:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cloud
  - aws
  - security-bypass
vendors:
  - AWS
products:
  - AWS API MCP Server (>= 0.2.13, < 1.3.47)
cves:
  - id: CVE-2026-16584
    cvss: 7
references:
  - https://github.com/advisories/GHSA-29w2-fq35-v728
---

A significant security vulnerability, CVE-2026-16584, has been identified in the open-source AWS API MCP Server, affecting versions 0.2.13 through 1.3.46. This server facilitates AI assistants' interaction with AWS services via AWS CLI commands, offering programmatic access with optional user-configured security policies to restrict specific AWS operations. The flaw occurs during server startup: if the data required for enforcing these security policies fails to initialize, the server continues running but silently skips all per-request policy checks for its entire runtime. This bypass allows any AWS API operations that would normally be restricted by the configured policy to proceed unimpeded, although the scope of potential actions remains constrained by the underlying AWS IAM permissions of the credentials used. The issue highlights a critical weakness where intended security controls can be rendered ineffective due to an initialization error, making it important for defenders to understand the server's operational integrity.

## Impact

When this vulnerability is triggered, the AWS API MCP Server operates without enforcing any of its user-configured security policies for the lifetime of the process. This means that specific AWS API operations, which the policy was designed to deny or gate, will execute without restriction. Although the server's actions are still bound by the AWS IAM permissions of the configured credentials, the intentional layer of defense provided by the MCP Server's policy is nullified. Organizations relying on this server for fine-grained access control to AWS resources could face unauthorized modifications, data access, or resource provisioning if this bypass is exploited. The affected versions range from 0.2.13 up to, but not including, 1.3.47.

## Recommendation

* Patch CVE-2026-16584 by upgrading to awslabs.aws-api-mcp-server version 1.3.47 or later immediately.
* Ensure any forked or derivative codebases incorporating the AWS API MCP Server are also patched to address CVE-2026-16584.
* Implement least-privilege IAM credentials for the AWS API MCP Server, such as a ReadOnlyAccess role, as IAM permissions remain the primary access control and are enforced regardless of the policy bypass.
* If the server started under degraded network connectivity, restart the server once connectivity is restored to ensure policy enforcement data loads successfully, preventing the CVE-2026-16584 bypass.
