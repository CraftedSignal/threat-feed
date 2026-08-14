---
title: Multiple Vulnerabilities in mchange-commons-java
slug: 2026-08-mchange-commons-java-vulnerabilities
description: mchange-commons-java versions prior to 0.6.0 are susceptible to JNDI injection and deserialization gadget attacks due to insecure ObjectFactory implementations and the ReferenceIndirector mechanism.
date: "2026-08-14T20:06:44Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - mchange
products:
  - mchange-commons-java (< 0.6.0)
  - c3p0 (< 0.14.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerabilities that this advisory addresses all begin with arranging for an application to lookup a malicious JNDI Reference or deserialize a malicious Java-serialized object.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This mechanism can be used to trigger well-known deserialization gadget chains... that will execute arbitrary commands on deserialization.
    confidence_band: high
cves:
  - id: CVE-2026-55153
    cvss: 7.1
    epss: 0.00327
references:
  - https://github.com/advisories/GHSA-h84g-69h7-mw6v
  - https://www.mchange.com/projects/c3p0/#security-note
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all Java applications utilizing mchange-commons-java and update to version 0.6.0.
      owner: IT Operations
      due: 72h
      evidence: Upgrading to the current version of mchange-commons-java is strongly recommended.
  mitigation_plan:
    - priority: immediate
      action: Implement Java serialization filters to restrict object deserialization.
      owner: IT Operations
      addresses: CVE-2026-55153
      evidence: Maintaining rigorous serialization filters can prevent many attacks.
---

The mchange-commons-java library, commonly used as a dependency for the c3p0 JDBC connection pool, contained multiple vulnerabilities in its `com.mchange.v2.naming.JavaBeanObjectFactory` class and `ReferenceIndirector` mechanism. Versions prior to 0.5.0 allowed `BinaryRefAddress` elements to be interpreted as Java-serialized objects, enabling the execution of arbitrary code via deserialization gadget chains if libraries like `commons-collections` are present on the classpath. 

Furthermore, versions prior to 0.6.0 permitted the `JavaBeanObjectFactory` to instantiate arbitrary classes and set properties. Attackers could leverage this via JNDI injection to perform actions such as SSRF (e.g., triggering HTTP requests via `JEditorPane`) or remote code execution. The `ReferenceIndirector` mechanism further facilitated these attacks by allowing malicious JNDI `Reference` objects to be smuggled through serialized data. These issues were addressed in version 0.6.0 by imposing class whitelisting, disabling deserialization support in the `ObjectFactory` by default, and disabling the `ReferenceIndirector`.

## Impact

The vulnerability impacts any Java application utilizing mchange-commons-java versions below 0.6.0, particularly those using the c3p0 connection pool. If exploited, an attacker could achieve remote code execution on the application server or perform server-side request forgery (SSRF). The success of deserialization-based RCE depends on the presence of vulnerable gadget chains within the application's classpath, while JNDI injection-based SSRF can affect environments regardless of secondary gadget availability.

## Recommendation

- Upgrade `mchange-commons-java` to version 0.6.0 or higher.
- Update `c3p0` to version 0.14.0 or higher, which includes the patched `mchange-commons-java` library transitively.
- If immediate patching is not possible, implement rigorous Java serialization filters (JEP 290/394) to block the deserialization of untrusted classes.
- Migrate to JVM version 16 or newer, as this makes internal JVM-based XSLT gadget chains inaccessible.
- Audit application classpaths to identify and remove unnecessary libraries containing known deserialization gadgets (e.g., `commons-beanutils`, `commons-collections`).
