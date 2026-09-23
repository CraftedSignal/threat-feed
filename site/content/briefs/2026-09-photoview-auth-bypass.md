---
title: Authorization Bypass Vulnerability in Photoview shareAlbum Mutation
slug: 2026-09-photoview-auth-bypass
description: Photoview versions through 2.4.0 contain an authorization bypass in the shareAlbum GraphQL mutation, allowing authenticated users to generate unauthorized share tokens for albums owned by others.
date: "2026-09-23T06:41:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:photoview:photoview:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - graphql
vendors:
  - Photoview
products:
  - Photoview (<= 2.4.0)
cves:
  - id: CVE-2026-96271
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96271
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Photoview to a version later than 2.4.0
      owner: IT Operations
      addresses: CVE-2026-96271
      evidence: NVD vulnerability disclosure for CVE-2026-96271
---

Photoview versions 2.4.0 and earlier are affected by an authorization bypass vulnerability located in the shareAlbum GraphQL mutation. The vulnerability permits an authenticated user to perform a GraphQL request specifying an arbitrary album ID, even if that album does not belong to the requesting user. The application fails to validate ownership of the target album before processing the request, resulting in the generation of a functional share token. An attacker can leverage this to create persistent public access links for private albums, exposing sensitive photo collections and nested sub-albums to unauthorized parties without the owner's knowledge. This issue poses a significant risk to data privacy for users deploying Photoview in multi-user or shared environments.

## Impact

Successful exploitation allows for the complete unauthorized exposure of private media collections. Because the generated share tokens provide persistent access, an attacker retains control over the shared link, potentially leading to widespread data exfiltration if the albums contain sensitive personal content. The vulnerability affects all users running vulnerable instances of Photoview, impacting personal or organizational storage instances.

## Recommendation

1. Upgrade to the latest version of Photoview beyond 2.4.0 to resolve the authorization logic flaw.
2. Audit current album share settings within the application to identify and revoke any suspicious or unauthorized tokens.
3. Restrict access to the GraphQL endpoint for unauthorized users if immediate patching is not possible.
