---
title: Authorization Bypass in @better-auth/stripe
slug: 2026-08-better-auth-stripe-auth-bypass
description: An authorization bypass vulnerability in @better-auth/stripe allows authenticated users to perform unauthorized subscription actions and access billing data of other organizations via ID parameter confusion.
date: "2026-08-01T13:54:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - web-vulnerability
  - billing
vendors:
  - Better Auth
products:
  - '@better-auth/stripe (1.4.11-1.6.20, 1.7.0-beta.0-1.7.0-beta.9)'
cves:
  - id: CVE-2026-67329
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67329
---

The @better-auth/stripe package contains an authorization bypass vulnerability (CVE-2026-67329) affecting versions 1.4.11 through 1.6.20 and specific 1.7.0 beta releases. The vulnerability arises from an inconsistency in how organization IDs are processed. The package middleware performs authorization checks by validating the organization ID provided in the request query string. However, the underlying handler retrieves the target organization ID directly from the request body, or defaults to the session-associated active organization. This discrepancy enables a user who is a member of multiple organizations to bypass authorization controls. By manipulating the request body or session context, a user can execute subscription operations - such as canceling plans, modifying billing, or accessing sensitive payment details - against organizations they are authorized to access as a member, but lack management permissions for. This vulnerability poses a significant risk to multi-tenant SaaS environments using the library for billing integration.

## Impact

Successful exploitation allows authenticated users to access billing details, including payment methods, invoices, and subscription states for organizations they do not manage. Furthermore, attackers can perform unauthorized administrative subscription actions, such as plan changes or account cancellations, resulting in potential service disruption and financial data exposure.

## Recommendation

1. Upgrade @better-auth/stripe to version 1.6.21 or 1.7.0-beta.10 or later immediately.
2. Review application logs for discrepancies between query parameter organization IDs and the organization IDs processed in request bodies during billing-related API calls.
3. Implement strict server-side validation that enforces a match between the authenticated user's session organization context and the organization identifier in the request body, regardless of query string parameters.
