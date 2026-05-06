---
title: Craft CMS GraphQL Address Resolver Missing Authorization Allows PII Disclosure
slug: 2026-05-craftcms-graphql-disclosure
description: A missing authorization check in the GraphQL Address element resolver of Craft CMS Pro allows a GraphQL API token scoped to a low-privilege user group to read all addresses in the system, including those belonging to users in groups the token is not authorized to access, exposing personally identifiable information (PII).
date: "2026-05-06T17:49:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - craftcms
  - graphql
  - pii
  - disclosure
vendors:
  - Craft CMS
products:
  - cms (>= 5.0.0, < 5.9.18)
  - cms (>= 4.0.0, < 4.17.12)
  - Craft CMS Pro
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-gj2p-p9m4-c8gw
  - https://github.com/craftcms/cms/commit/834b2cf61ad0dcee9b03add44ed402ebf18db128
rules:
  - title: Detect CraftCMS GraphQL Address Resolver Unauthorized Access
    description: Detects potential unauthorized access to the CraftCMS GraphQL Address resolver by monitoring for requests to the `/actions/graphql/api` endpoint containing a GraphQL query for addresses, which may indicate an attempt to exploit the missing authorization check.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - webserver
      - linux
  - title: Detect CraftCMS GraphQL ownerId Parameter Abuse
    description: Detects potential IDOR attempts via the `ownerId` parameter in CraftCMS GraphQL address queries, indicating targeted reconnaissance against specific users.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A missing authorization check in Craft CMS Pro's GraphQL Address element resolver (src/gql/resolvers/elements/Address.php) allows unauthorized access to sensitive user data. Specifically, a GraphQL API token with limited permissions (e.g., read access to a single low-privilege user group) can bypass intended scope restrictions and retrieve all addresses within the system. This includes addresses associated with users belonging to groups the token should not have access to, effectively exposing PII. This vulnerability affects Craft CMS Pro versions 4.0.0 through 5.9.17 and presents a significant risk to data confidentiality, especially for organizations using GraphQL APIs for headless CMS deployments. The issue was identified through manual source code review with AI-assisted analysis.

## Attack Chain

1.  Attacker obtains a GraphQL API token with read access to at least one user group within Craft CMS.
2.  Attacker introspects the GraphQL schema using a query to discover the available top-level queries, including `addresses`.
3.  Attacker queries the `AddressInterface` to identify exposed fields, such as `fullName`, `addressLine1`, `organization`, and `organizationTaxId`, revealing potential PII.
4.  Attacker makes a baseline query to the GraphQL API using the token to confirm the token's user scope is limited. This confirms the token only has access to a specific user group.
5.  Attacker issues a query to retrieve all addresses using the GraphQL API, bypassing intended scope restrictions.
6.  The API returns address data for ALL user groups, including those outside the token's authorized scope, exposing PII of users in restricted groups.
7.  Attacker leverages the `ownerId` argument to perform an IDOR attack, targeting specific users' addresses by their IDs without proper authorization.
8.  Attacker extracts sensitive address information, including corporate tax IDs, for internal users they should not have access to, completing the data exfiltration.

## Impact

The vulnerability allows an attacker with minimal permissions to extract sensitive PII, including full names, home addresses, organizations, and tax IDs. This poses a direct threat to user data privacy and organizational security. All Craft CMS Pro sites (v4.0.0+) that use GraphQL API tokens with user group scoping and store user addresses are potentially affected. The targeted extraction via IDOR can lead to reconnaissance against high-value users like administrators. If successful, the attacker can gain unauthorized access to confidential information, leading to potential financial loss, reputational damage, and legal repercussions.

## Recommendation

*   Upgrade Craft CMS to versions 5.9.18 or 4.17.12 or later to patch CVE-2026-44010.
*   Deploy the Sigma rule `Detect CraftCMS GraphQL Address Resolver Unauthorized Access` to your SIEM to detect exploitation attempts.
*   Review and restrict the permissions of GraphQL API tokens to follow the principle of least privilege, minimizing the potential impact of unauthorized access.
*   Monitor web server logs for unusual GraphQL queries targeting the `addresses` endpoint.
