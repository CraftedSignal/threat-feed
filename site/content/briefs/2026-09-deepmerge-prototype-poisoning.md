---
title: Prototype Pollution Vulnerability in deepmerge
slug: 2026-09-deepmerge-prototype-poisoning
description: The deepmerge library up to version 4.3.1 contains a prototype pollution vulnerability in the mergeObject() function, allowing attackers to inject malicious properties into objects.
date: "2026-09-18T20:07:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deepmerge_project:deepmerge:*:*:*:*:*:node.js:*:*
products:
  - deepmerge (<= 4.3.1)
cves:
  - id: CVE-2026-93753
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93753
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Security Operations
  immediate_actions:
    - action: Audit dependency manifests (package-lock.json, yarn.lock) to identify vulnerable versions of deepmerge.
      owner: Development Teams
      due: 48h
      evidence: CVE-2026-93753 metadata
  mitigation_plan:
    - priority: immediate
      action: Upgrade deepmerge to the patched version as indicated by the project maintainers.
      owner: Development Teams
      addresses: CVE-2026-93753
      evidence: NVD vulnerability entry
---

The popular deepmerge JavaScript library, specifically versions 4.3.1 and below, contains a prototype pollution vulnerability within its mergeObject() function. The flaw stems from insufficient validation of keys being processed during object merge operations. When an application utilizes this library to merge user-supplied input into an existing object, an attacker can craft a malicious source object containing sensitive keys, such as __proto__ or constructor, to overwrite prototype properties. This allows an attacker to inject arbitrary values that will then be inherited by other objects within the application's runtime. If the downstream application performs property access without explicit own-property checks, these injected values can influence logic, potentially leading to denial of service, security bypasses, or remote code execution depending on how the application uses the tainted properties.

## Impact

Successful exploitation allows attackers to pollute the global object prototype, which may alter the behavior of an application in unintended ways. Potential consequences include bypassing authentication checks, modifying application logic, or causing application crashes. Given the library's widespread use in Node.js and browser-based JavaScript environments, the scope of affected software is significant.

## Recommendation

Prioritize the identification and patching of any application using deepmerge version 4.3.1 or earlier.

- Upgrade the deepmerge package to a version that addresses CVE-2026-93753.
- Review codebases for the use of deepmerge where user-supplied input is passed directly to the merge function without prior sanitization or schema validation.
- Implement recursive object freezing or use Object.create(null) for target objects where applicable to mitigate the risk of prototype pollution.
