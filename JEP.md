Summary
-------

Extend the Java Cryptographic Architecture (JCA) with a filtering mechanism to configure which services, implemented by installed security providers, are enabled in run time.


Goals
-----

The main goal of this proposal is to implement a filtering mechanism to constrain which services, implemented by installed security providers, are available for use in the `getInstance` JCA APIs (Cipher, Signature, Mac, KeyFactory, etc). A service that is not enabled by the filter should not be eligible for use as if its security provider did not implement it.

The filtering mechanism should apply to services implemented either by statically installed security providers (i.e. defined by `security.provider.<n>` Security properties) or dynamically installed ones (i.e. added with the `java.security.Security::addProvider` API). No distinctions should be made between OpenJDK and third-party security providers.

The services filter has to be configurable by means of a Security property, overridable with a System property of the same name. As for the syntax of this property, the following characteristics are desired: 1) support service identification per provider name, service type and algorithm name or alias; 2) include constructs to select multiple services by a single rule (e.g. all services of a certain service type); 3) support expressing rule actions in an allow or deny-like manner; and 4) be concise, simple and unambiguous. Given the security sensitive nature of this feature, any syntactic error in the filter value should be fatal. In order to facilitate troubleshooting, error and diagnostic logging should be implemented.


Non-Goals
---------

When a service is not allowed by a filter, dependent application or library functionality will stop working. Further affected functionality could be a service that uses a disabled service as a building block. It is not a goal of this proposal to implement a mechanism to warn about dependent functionality potentially affected by a given filter value. In addition, a filter value entered by a user may include redundant or superfluous rules. These rules will not be detected or cleaned up automatically. Users of this feature are expected to perform an assessment to understand and validate the implications of disabling a service, and at the same time ensure internal consistency for the filter value set.

This proposal does not aim to standardize algorithm names across OpenJDK and third-party security providers. When defining a filter value, services implemented by installed security providers and their algorithm names or aliases must be known. It is important to consider that security providers may use slightly different names for the same algorithm, or may not define the same aliases.

It is not a goal to implement filtering capabilities based on service clients (i.e. allowing or denying a service depending on which class, package or module is trying to use it). In addition, identifying services with a granularity finer than an algorithm name or alias (e.g. based on key size or other algorithm parameters) is not under the scope at this time. With that said, extensions to this proposal may be explored in the future and characters such as `:` and `,` will be reserved in the filter syntax for this purpose.

It is out of the scope to implement an API that supports the definition of filter values dynamically with Java code, in the same way that `java.io.ObjectOutputStream::setObjectInputFilter` does for serialization filters. Furthermore, filters should be immutable. It is not a goal to implement a mechanism to reinitialize or modify a filter value in run time.

The filter is not a framework to assist security providers to achieve their FIPS certification requirements. A security provider must only register the algorithms for which it has been certified, with the appropriate parameters, and should not delegate or externalize this decision to the filter.

Success Metrics
---------------

Whereas all listed goals of this feature are either binary or qualitative, it is still relevant to define numerically quantifiable metrics to ensure that no performance regressions in the JCA APIs are introduced. Meeting the following performance metrics is required for success:

1. An empty filter must not cause any performance regression. This type of filter, configured in OpenJDK by default, would not block any service.

2. A non-empty filter may cause a negligible performance penalty both during JCA initialization and provider registration, but must not cause any impact at service use time. The penalty expected during JCA initialization is due to filter parsing and should be of order _O(n)_, with _n_ being the number of characters in the filter value. At provider registration time, a performance penalty is expected due to the evaluation of services against the filter. This evaluation shall occur only once per service.


Motivation
----------

Current configuration capabilities in the JCA allow users to install security providers statically or dynamically, decide their preference in an ordered list and even circumvent this order for specific services. However, there is no granularity in terms of which services installed security providers bring with them: it is an _all_ or _none_ decision. Historically, security providers lump together services of various types. As an example, the SUN security provider comes with services of the following types: SecureRandom, Signature, KeyPairGenerator, AlgorithmParameterGenerator, AlgorithmParameters, KeyFactory, MessageDigest, CertificateFactory, KeyStore, CertStore, Policy, Configuration, CertPathBuilder and CertPathValidator. This lack of flexibility in provider configuration negatively affects scenarios where policy compliance is required.

### FIPS 140 compliance

For FIPS 140 compliance, cryptographic operations shall be done within a FIPS-certified module. In OpenJDK, the SunPKCS11 security provider can be configured with a FIPS-certified hardware or software module, such as the NSS Software Token. Other third-party security providers like Bouncy Castle may also be FIPS-certified.

Security providers bundled in OpenJDK (SUN, SunJCE, SunEC, etc.) are not FIPS-certified but may be still needed for X.509 certificates support, TLS or other non-cryptographic functionality. The problem is that they bring with them non-FIPS cryptography that, if inadvertently used, would compromise the overall compliance.

Ordering installed security providers in descending preference is not enough to resolve this issue because of the fallback scheme: if an algorithm is not found in a preferred provider, it will be looked up in a less preferred one. The FIPS 140 compliance use case would benefit if policy enforcement at the security provider level ensures that non-compliant cryptographic services are disabled.

### Cryptographic policies

Cryptographic algorithms could weaken or become unsuitable for use over time, compromising information security and regulations compliance. For this reason, most organizations periodically review and enforce policies that establish which cryptographic algorithms are allowed for use.

While OpenJDK has Security properties to limit cryptographic algorithms for TLS, certificate path validation and JAR signing, these restrictions do not apply to JCA APIs (Cipher, Signature, Mac, etc). Thus, an installed security provider could bring a service implementing an algorithm that violates a defined policy and make it available for an application to use.

The proposed filtering mechanism supports enforcement of cryptographic policies across all JCA APIs by defining the algorithms that should be either blocked or allowed. In any case, a cryptographic policy can be enforced and updated easily at system administrator's discretion.

In particular, mainstream Linux distributions can further extend the reach of _crypto-policies_ alignment and enforce these policies over all OpenJDK JCA APIs. _Crypto-policies_ is a package that contains curated lists of cryptographic algorithms according to security profiles that can be set globally in the operating system. Security profiles provide different levels of security hardening that lean more towards backward compatibility, complying with regulations such as FIPS, establishing a secure default or anticipating future requirements. Each of these profiles would have a filter value according to the algorithms that should be allowed or blocked.

### Checkpoint/Restore In Userspace (CRIU) safety assessment

For CRIU use cases, a snapshot of the JVM process is taken once and resumed multiple times. The reuse of cryptographic pseudo-random numbers, secrets or keys may weaken or compromise the security of the system. The proposed filtering mechanism would be beneficial to enforce a cryptographic policy that disables random value generators and key generators and then assessing if there were any issues while taking a snapshot. If there were not, it is reasonable to assume that the application is safe for CRIU use.

### Interoperability, performance and other policies

For interoperability, the use of standard algorithms may need to be enforced. As an example, storing keys and certificates in a PKCS \#12 format could be necessary for interoperability with other systems. The proposed filtering mechanism can be used to enforce this type of policy.

Performance is also a possible reason for the enforcement of a policy. If a security provider is significantly faster than others, a policy may require that all operations of a specific type should be done with it. If an algorithm is not supported by the fastest provider, the filtering mechanism proposed would prevent a silent fallback to a slower implementation.

More generally, an organization can control which security providers, service types and algorithms are used according to a defined policy or criteria. This proposal does not constrain policies to fixed cases but gives flexibility for customization to specific needs.

In summary, all the previous use cases may benefit from this proposal in terms of security, compliance, performance and interoperability. What is common to these cases is the enforcement of a defined policy across all JCA components for every application running on a specific JDK deployment. The filter mechanism is envisioned as a flexible and powerful tool for system administrators and packagers alike. As such, it requires an intermediate level of understanding of the JCA, the installed security providers and its own documentation.

The enforcement of a policy may have two possible and intended outcomes for an application: 1) automatic compliance with the policy —e.g. switch to an algorithm that is allowed—, or 2) error throwing for manual corrective action to be taken —e.g. a `java.security.NoSuchAlgorithmException` exception—. In any case, the risk of an inadvertent policy breaching should be mitigated.

Achieving the same level of policy enforcement without the proposed filtering mechanism would be more difficult, error-prone and even not feasible in some cases. It would require an open-box approach to audit source code, configurations and generated logs for every application running on a JDK deployment to detect uses of the JCA that are not compliant. The automatic policy adaptation advantage, previously described as outcome \#1, would not be available.


Description
-----------

This proposal is for a configurable filter to enable or disable services implemented by installed security providers. The filter is initialized along with the security providers classes, using either the value of the `jdk.security.providers.filter` Security property or a System property of the same name. If the System property is passed, it supersedes the Security one. Both properties are updateable at runtime which leaves a window for runtime code to side-effect the configuration prior to filter initialization. However, once the filter has been initialized subsequent runtime property updates will not cause the filter to be reset. When a filter is not set or is set to the empty string, filtering is disabled: all services are allowed.

The filter applies to services implemented by both OpenJDK and third-party providers, either statically with a `security.provider.<n>` Security property or dynamically with the `java.security.Security::addProvider` API. Filtering is enforced according to a multi-layer strategy, capable of blocking services at different levels. This strategy is designed to cover common and special cases with maximum efficacy. For most providers —including OpenJDK's—, services are filtered in `java.security.Provider::put` or `java.security.Provider::putService` methods, and never returned in `java.security.Provider::getService` or `java.security.Provider::getServices`. For third-party providers that override `java.security.Provider::getService` or `java.security.Provider::getServices` to return services that have not been evaluated against the filter or are evaluated and not allowed, a second filter enforcement occurs in `java.security.Provider.Service::newInstance`. In rare situations, a third-party provider can override `java.security.Provider.Service::newInstance` and return an unvetted service implementation (SPI). As a last layer of defense, services are checked in `::getInstance` APIs. For the last defense to be effective, the service type must be one of the available in the JDK (Cipher, Signature, Mac, etc.). Third-party service types cannot take advantage of this check as the filter does not expose a public API.

Each service is evaluated by the filter only once in its lifetime, before use. A service that is rejected by the filter cannot be used in any of the JCA APIs, as if it were not implemented by its security provider. Depending on services availability, attempting to use a service blocked may result in a `java.security.NoSuchAlgorithmException` exception or the return of a different implementation for the same algorithm, according to the preference order of installed security providers.

OpenJDK has Security properties for disabling algorithms in the TLS, JAR signing and certificate path validation subsystems (`jdk.tls.disabledAlgorithms`, `jdk.jar.disabledAlgorithms` and `jdk.certpath.disabledAlgorithms` respectively). This existing mechanism applies on top of the proposed filter. Thus, for an algorithm to be available, it has to be allowed by both the existing mechanism and the proposed filter.

Services are identifiable as a combination of a security provider, a service type and an algorithm name. Optionally, an algorithm alias can be used to replace the algorithm name. A filter is made of a sequence of patterns that identify a service according to a matching criteria —as we shall see later— and indicate an action: allow or deny the service under evaluation.

The filter syntax is as follows:

`pattern-1; pattern-2; ...; pattern-n`

Each pattern in the sequence can be optionally prefixed by a `'!'` character (e.g. `! pattern-1`). White spaces between patterns, pattern prefixes (`'!'`) and pattern separators (`';'`) are not significant. A service is evaluated against the filter from left to right. If a service matches one of the patterns in the sequence, an authorization decision is made: if the pattern is prefixed by a `'!'` character, the decision is to deny it; otherwise, the decision is to allow it. If none of the patterns match, the default decision is to deny the service. Once a decision is made, remaining patterns are not considered.

Each pattern's syntax has one of the following forms:

1\. `security-provider`

2\. `security-provider.service-type`

3\.a\. `security-provider.service-type.algorithm-name`

3\.b\. `security-provider.service-type.algorithm-alias`

3\.c\. `security-provider.Cipher.transformation`

3\.d\. `security-provider.Cipher.transformation-alias`

In form \#1, a security provider name equal to _security-provider_ is enough for a match to be successful. In form \#2, the service type must also be equal to _service-type_. In form \#3.a, the service algorithm must also be equal to _algorithm-name_. In form \#3.b, it is enough that one of the service aliases matches _algorithm-alias_, in addition to the requirements for form \#2. Form \#3.c is similar to form \#3.a but applies to cipher transformations with multiple components (`algorithm/mode/padding`). Form \#3.d is equivalent to \#3.c but looks for a transformation alias match (`algorithm-alias/mode/padding`). In all cases, pattern and service names must have valid characters and cannot be empty. Pattern matching is always case insensitive.

Characters `'\n'` and `'\0'` are not valid in a pattern. The character `'.'` is used as a separator between different levels: security provider, service type, algorithm name or algorithm alias. The following characters, when part of one of the listed levels, must be escaped by prepending a `'\'` character: `'!'`, `'*'`, `' '` (white space), `'.'`, `';'`, `'\'`, `':'` and `','`. Escaping any other character has no effect other than silently discarding the `'\'` character.

It is worth mentioning that these escaping rules apply to the filter value as read in the `java.security.Security::getProperty` and `java.lang.System::getProperty` APIs: additional escaping might be needed depending on how the filter value is passed. For example, Security properties require `'\'` characters to be escaped. Thus, to match a provider whose name is _abc\\123_, a pattern must be escaped as _abc\\\\\\\\123_ if passed as a Security property.

In addition to character escape sequences, pattern names can contain `'*'` wildcards to imply zero or more repetitions of any character. Wildcards behave in greedy mode, trying to consume as many characters as possible and backing off if necessary.

When a service has aliases, its algorithm name and each of the aliases are independently evaluated against the filter. Notice that the security provider and service type for each of these evaluations are the same. From the set of authorization decisions obtained —which can potentially be contradictory—, the one made by the left-most pattern in the filter has the highest priority and is finally effective. This strategy would be equivalent to modifying the evaluation of a service against each pattern so that each alias is tried (besides the algorithm name) and stopping if a decision is made for one of them.

For troubleshooting, it is possible to enable filter debugging logs with the System property `java.security.debug=jca` and look for messages prefixed by _ProvidersFilter_. To list services allowed and not allowed by a filter for each installed security provider, run java with the argument `-XshowSettings:security:providers`. When a filter value is syntactically invalid, the exception message thrown points to the exact location in the pattern that could not be parsed.

### Consistency between security providers when blocking building block services

It is assumed that applications and libraries get instances of services through the JCA APIs and not by creating instances of their implementation classes directly, which are often private. If the latter were to happen, the filter would be ineffective to block a service.

The implementation of a service itself may require another service as a building block. For example, a Signature service for the algorithm SHA256withECDSA could use a MessageDigest service for the algorithm SHA256. However, a SHA256withECDSA service from a different provider may handle this dependency by creating an instance of the building block's implementation class directly, instead of going through the JCA.

As a result, blocking a building block service may exhibit different behavior in dependent services between security providers. For example, blocking the service MessageDigest SHA256 may cause the service Signature SHA256withECDSA to stop working on a provider that obtained it through the JCA but does not affect one that creates an instance of its implementation class.

To mitigate the risk of confusion, documentation and guidelines will be elaborated indicating how to write an effective filter regardless of the security provider. Going back to the previous example, a filter blocking the service MessageDigest SHA256 **shall not** be assumed to have any effect on the service Signature SHA256withECDSA: if the service Signature SHA256withECDSA has to be blocked, the filter must have a rule for it. On the other hand, blocking MessageDigest SHA256 **may** cause other functionality —even beyond Signature SHA256withECDSA— to stop working.

### The JCA Cipher API and transformations

The Cipher API has a behavior that sets it apart from other JCA APIs. Algorithm names, referred to as transformations, are of the form `algorithm` (single component) or `algorithm/mode/padding` (multi-component). In a multi-component form, one of mode and padding may be empty but not both. If both components are empty, the single component form is used instead (i.e. _algorithm//_ is handled as _algorithm_). Multiple components transformations require special attention as they could be a source of confusion when defining a filter.

When looking for services to support a multi-component transformation, four possible derivatives are tested as service algorithm or alias: _algorithm/mode/padding_, _algorithm/mode_, _algorithm//padding_ and _algorithm_. For example, if the transformation in a `Cipher::getInstance` call is AES/CBC/PKCS5Padding, services with algorithm or aliases AES/CBC/PKCS5Padding, AES/CBC, AES//PKCS5Padding and AES are searched by means of the `Provider::getService` API. A service may support a transformation even if its algorithm name and aliases do not match the transformation exactly, as in the last three cases of the previous example. The Cipher API does further checks in these cases to determine if the service actually supports the transformation.

To illustrate how the previous case may be confusing, let's assume that the transformation AES/CBC/PKCS5Padding has to be allowed and everything else blocked. A natural filter value would be `*.Cipher.AES/CBC/PKCS5Padding; !*`. One service candidate to support the transformation is SunJCE's AES Cipher. However, this service would not be allowed by the filter. To address this problem, special handling of cipher transformations has to be implemented. This handling applies only to cases in which the transformation has multiple components and is different from the service algorithm and aliases.

A service candidate to support a transformation has to be evaluated against the filter based on the transformation, and not its algorithm or aliases. The provider and type of the candidate service are correct for the evaluation, though. Possible transformation aliases need to be analyzed as well. Transformation aliases are built by iterating the service algorithm and aliases, extracting their first component after a `'/'` split and appending the transformation mode and padding to them.

For example, in a `Cipher::getInstance("AES/CBC/PKCS5Padding")` call, the Cipher service AES from SunJCE is a candidate to support the transformation. For filter evaluation, the following transformation and transformation aliases are considered:

1. AES/CBC/PKCS5Padding
2. OID.2.16.840.1.101.3.4.1/CBC/PKCS5Padding
3. 2.16.840.1.101.3.4.1/CBC/PKCS5Padding

\#1 is the transformation; equal to splitting the service algorithm by `'/'`, extracting its first component ("AES") and appending the transformation mode and padding. \#2 and \#3 are transformation aliases based on the service aliases; after splitting each alias by `'/'`, taking its first component and appending the transformation mode and padding. The service would be allowed by transformation \#1.

Transformation \#1 and its \#2 and \#3 aliases are equivalent arguments for a `Cipher::getInstance("transformation")` call: the same SunJCE AES Cipher service is returned. The filter provides support for transformation aliases in a way that is consistent with regular (non-transformation) aliases.

### Examples of correctly defined filter values

Enable all security providers, service types and algorithms:

`jdk.security.providers.filter=`

or

`jdk.security.providers.filter=*`

or

`jdk.security.providers.filter=*.*`

or

`jdk.security.providers.filter=*.*.*`

--

Enable all services except for SUN's MessageDigest implementation of the MD5 algorithm:

`jdk.security.providers.filter=!SUN.MessageDigest.MD5; *`

--

Enable all services except for MessageDigest implementations of the MD5 algorithm, irrespective of the security provider:

`jdk.security.providers.filter=!*.MessageDigest.MD5; *`

--

Enable all services except those involving the algorithms MD2 or MD5; irrespective of the security provider, the service type and the exact algorithm name:

`jdk.security.providers.filter=!*.*.*MD2*; !*.*.*MD5*; *`

Notice in this example the wildcards at the beginning and end of the algorithm names. Their purpose is to extend the matching reach to include HmacMD5, MD5withRSA and PBEWithMD5AndDES among others.

--

Enable all SunJCE services except for AES cipher transformations using ECB mode, irrespective of the padding scheme.

`jdk.security.providers.filter=!SunJCE.Cipher.AES*/ECB/*; !SunJCE.Cipher.AES; SunJCE`

Notice in this example how the first pattern blocking the ECB mode matches the transformations starting with AES, AES_128, AES_192 and AES_256. In addition, the AES algorithm has to be blocked by the second pattern because SunJCE's AES service uses ECB mode by default. AES_128, AES_192 and AES_256 algorithms without mode and padding are not registered by SunJCE and do not require special handling. Blocking AES*//* is not necessary because the empty-string mode is not supported anyways.

Other providers may define different values for algorithm names, default modes and even support the empty-string mode. It is recommended to analyze each provider before writing a filter. With that said, the following filter value may be worth considering as a starting point to block all AES transformations using ECB mode, irrespective of the provider:

`jdk.security.providers.filter=!*.Cipher.AES*/ECB/*; !*.Cipher.AES*//*; *.Cipher.AES*/*/*; !*.Cipher.AES*; *`

--

Enable all services except for SunJCE's Cipher implementation of the RC4 algorithm:

`jdk.security.providers.filter=!SunJCE.Cipher.ARCFOUR; *`

or

`jdk.security.providers.filter=!SunJCE.Cipher.RC4; *`

or

`jdk.security.providers.filter=!SunJCE.Cipher.1\.2\.840\.113549\.3\.4; *`

Notice in this example how either the algorithm name or any of the aliases can be used for the same purpose.

--

Enable the SUN security provider only, with all its service types and algorithms. Services implemented by other security providers should be disabled.

`jdk.security.providers.filter=SUN`

or

`jdk.security.providers.filter=SUN; !*`

Notice how in the first value for this example the implicit rule of blocking anything that does not match a pattern takes effect.

--

Enable the SUN security provider only, with all its service types and algorithms except for MessageDigest. Services implemented by other security providers should be disabled.

`jdk.security.providers.filter=!SUN.MessageDigest; SUN`

Notice how in this example the more specific pattern involving the SUN security provider is located left to the most general one. Otherwise, the general pattern will make a decision for all services implemented by SUN, including MessageDigest, and the specific pattern would be ignored.

### Examples of incorrectly defined filter values

Enable all services except for the HmacMD5 algorithm, irrespective of the security provider and the service type:

`jdk.security.providers.filter=*; !*.*.HmacMD5`

This is incorrect because the rule `"*"` matches and allows any service, while the rule blocking HmacMD5 is always ignored. The correct filter value for this example would be: `!*.*.HmacMD5; *`

--

Enable all services implemented by SUN except for MessageDigest. Services implemented by other security providers should be disabled.

`jdk.security.providers.filter=!SUN.MessageDigest`

While both SUN's MessageDigest services and services implemented by other security providers are disabled, SUN's non-MessageDigest services are not enabled. The correct filter value for this example would be `!SUN.MessageDigest; SUN`

--

Enable all services implemented by the SunPKCS11 security provider. Services implemented by other security providers should be disabled.

`jdk.security.providers.filter=SunPKCS11`

This is incorrect because the SunPKCS11 provider has to be identified by its name and not its class. A valid name would have the form of _SunPKCS11-SomeName_. A correct filter value for this example would be `SunPKCS11-SomeName or SunPKCS11-*`


Alternatives
------------

### Rearrange security providers by services type

The idea for this alternative is to rearrange security providers in a way such that services of different types are not mixed together. This new arrangement would allow service type granularity at the time of installing a security provider. For example, to address the FIPS use case described in section _Motivations_, the non-FIPS security provider offering X.509 certificates support would be installed without bringing non-FIPS certified cryptography in the same bundle.

These are some of the drawbacks that have been identified for this alternative:

- Rearranging OpenJDK security providers would be a major compatibility breaker. Applications, based on public JCA documentation, may expect a service to be found in a specific security provider. When a JCA API is invoked, the security provider implementing the algorithm may be passed. For example, a `Signature.getInstance("SHA256withDSA", "SUN")` invocation expects the SUN security provider to implement a Signature service for the SHA256withDSA algorithm. This type of invocation would be broken if Signature services are moved from SUN into a different security provider.

- It is not possible to enforce changes on third-party security providers, reducing the effectiveness and scope of this approach.

- Even if security providers were rearranged by service type, it is not possible to achieve granularity at the algorithm level. This would not support some of the use cases described in the _Motivations_ section.

### Services shadowing

In this approach we explored filtering services by shadowing them with a mock security provider. Two variations of this concept were sketched out:

#### Variation 1

The mock provider would be installed first in order of preference. For service types and algorithms that have to be blocked, the mock provider would register them and return instances that, upon use, throw an exception. This strategy would prevent the real service from being returned and used. When a service has to be allowed, the mock provider does not return an instance and the fall back mechanism gets the service from the real provider (if available).

These are some of the drawbacks that have been identified for this variation:

- It would not be possible to block services when their security provider is passed as part of the JCA API invocation. Additionally, there is no granularity to block services based on their security provider.

- Exceptions would be thrown lazily, making it difficult for applications to handle failures and looking for alternative services. After a JCA invocation, the returned service type instance is expected to work. Any changes in this respect could affect compatibility.

- Applying policies that block all algorithms of a given type would be difficult because it requires a comprehensive enumeration of all algorithms. Policies of the allow-list type would also require a comprehensive enumeration of all algorithms and service types because this variation can only block services.

#### Variation 2

Alternatively, the mock provider can impersonate providers from the installed list while keeping references to them. By overriding `java.security.Provider::getService`, the mock provider can capture all service type and algorithm requests and return either `null` or a real service according to its internal filtering logic. In other words, the filter would be implemented inside a security provider.

These are some of the drawbacks that have been identified for this variation:

- The application can dynamically install a security provider higher in order of preference than the mock provider. If so, the mock provider would be unable to impersonate the new provider and filter its services.

- This approach has high complexity and the security providers framework has not been designed for this type of use.

### Preferred algorithms only

In this alternative a new boolean Security property is introduced to optionally redefine the semantics of the existing 
`jdk.security.provider.preferred` property. With the new semantics, preferred services would be the only ones allowed. A suitable name for the new property would be `jdk.security.provider.preferredOnly`.

These are some of the drawbacks that have been identified for this alternative:

- Overloaded property semantics may lead to user confusion. There is no precedent for this type of behavior in a Security property.

- The current syntax for preferred services does now allow to include multiple services in a single rule, making it highly verbose and error-prone when listing large numbers of services.

- It would not be possible, with the current syntax for preferred services, to implement a deny-list strategy for blocking services.

- While the syntax can be extended, it would be difficult to do it in a way that is consistent and meaningful for both semantics.

### Alternative syntaxes for a Security Providers Filter

The proposed filter syntax is inspired by existing Security properties such as the object serialization filter, the RMI Registry filter, the JNDI filters (global, LDAP and RMI) and the preferred providers list. While domain specific changes are needed to filter JCA services, many of the reserved characters and constructions retain their semantics: list of patterns ordered from left to right, separation of patterns by `';'`, use of `'!'` for rejection actions, availability of `'*'` wildcards for pattern matching, identification of services by `service-type.algorithm` or `cipher.transformation` sequences and, more loosely, the concept of matching all services when the service type or algorithm levels are not specified. The rationale behind this decision is to leverage on user familiarity to existing filtering grammars in OpenJDK and reduce the learning curve. At the same time, the JCA services domain is different enough from other class-based filters for users to expect specificity.

Nonetheless, alternative filter syntaxes have been explored. These efforts have gone in the direction of adding verbosity to patterns so the context for each filter component is made explicit. For example, a pattern like `!SUN.MessageDigest.MD5; !*.MessageDigest.SHA*; *` in the proposed syntax could be equivalent to `{ provider: SUN; service-type: MessageDigest; algorithm: MD5; decision: reject } and { provider: ALL; service-type: MessageDigest; algorithm: { startsWith: SHA }; decision: reject } and { provider: ALL; service-type: ALL; algorithm: ALL; decision: allow }` in an alternative syntax. Virtually infinite variations and compromises between a highly compact and a fully verbose syntax can be laid out, but all of them were found to offer an equal expressiveness power.

The following drawbacks have been identified for the alternative syntaxes explored:

- Central aspects of the filter complexity are not eliminated. A filter definition would still require learning about pattern-based matching of services, considering order-dependent pattern rules and having a good understanding of both the JCA and the installed providers. High level actions such as blocking all uses of an algorithm or blocking a cipher encryption mode may still be composed of multiple low-level patterns, even interleaving allow and reject actions, but be harder to visualize. Benefits tend to be more on the peripheral side.

- Additional verbosity makes filters longer and more difficult to read unless proper indentation is applied. Filter values passed as System properties would be particularly affected. Support for defining filters in external files would probably be required with this approach.

- Users will not find familiarity with existing OpenJDK security filters and learning an unrelated language would be necessary. A language with more reserved words, constructs and rules can potentially increase complexity, require a longer learning process and could open up space for interpretation, ambiguity or inconsistency.

   To illustrate this point, let's extend the previously suggested syntax by introducing a new construct to support Cipher transformations. Blocking the AES algorithm with ECB mode and PKCS \#5 padding may look like `{ provider: ALL; service-type: Cipher; transformation: { algorithm: AES; mode: ECB; padding: PKCS5Padding }; decision: reject }`. While this example looks straightforward at first glance, questions arise when looking in more detail: Can the transformation and algorithm blocks be used at the same nesting level? Are mode and padding assumed to match all values if not specified in a transformation block? What happens if a transformation block is added when a service is not of the Cipher type? or, if the service type is Cipher and an algorithm block is used?

   A more compact syntax, with flat interpretation (e.g. simple text matching), consistent at every level (provider, service type and either algorithm or transformation), helps to reduce the risk of unexpected interactions between language constructions.

### Filtering at the ::getInstance API level only

As an alternative, we explored simplifying the multi-layer filtering mechanism, removing `java.security.Provider::put`, `java.security.Provider::putService` and `java.security.Provider.Service::newInstance` checks to leave `::getInstance` ones only. While this approach would require a thinner implementation, it lacks efficacy and consistency in comparison to the one proposed. In practical terms, third-party service types will be out of the scope of the filter or the filter would require a public API for this to be addressed. For the latter case, third-party libraries cooperation would be needed, leaving room for inconsistent behavior.

In the interest of having a powerful, flexible and long-term solution for the filter, we lean towards an in-depth filtering strategy.

### Leveraging on the existing java.security.Provider::configure API to configure security providers

Security providers can optionally implement the `java.security.Provider::configure` API to receive initialization configurations as strings. The SunPKCS11 security provider is the only implementor of such API in the JDK libraries at the moment, and uses it to receive the configuration for the underlying PKCS \#11 library. In this alternative we explore leveraging this API for filter configuration, instead of adding Security and System properties.

There are multiple downsides to this approach. The list that follows does not aim to be exhaustive but enough to rule it out:

- While the provider part of the pattern specification in the filter may be avoided, the gain in simplicity is negligible as a syntax specification would still be required for the service type, algorithm and algorithm alias components.

- For SunPKCS11 and for third-party security providers that currently implement `java.security.Provider::configure`, any requirement affecting the configuration string received by parameter would be compatibility breaking. The current public API does not prescribe anything for the value of the `configArg` parameter.

- Third-party security providers that override `java.security.Provider::configure` would need to intentionally apply filtering actions. Without a public filter API, this would probably lead to boiler-plate code. In any case, this opens the door for inconsistency and security risks.

- The capacity to filter irrespective of the security provider would be negatively impacted as configurations would be per-security provider. In a static configuration scenario, the user would need to write filter values for each installed security provider. In a dynamic configuration scenario, this translates into invoking `::configure` over each provider instance. In any case, this would lead to filter value duplication and increase the risk of misconfiguration. For example, blocking the AES algorithm would need to be specified for SunJCE, for SunPKCS11 and potentially for third-party security providers. Furthermore, the static or dynamic installation of new security providers would require an explicit configuration.


Testing
-------

In order to validate the implementation of this proposal, a testing harness capable of spawning JVM processes with filter values passed as a Security property will be developed. Over this harness, the following categories of test cases will be implemented:

1. Allow-list services filtering by security provider, service type, algorithm or alias.

2. Deny-list services filtering by security provider, service type, algorithm or alias.

3. Filtering of services with multiple aliases.

4. Filtering of services by transformation and transformation aliases.

5. Filtering of services implemented by statically and dynamically installed security providers.

6. Filtering of services implemented by OpenJDK and third-party security providers.

7. Filter values requiring escaping of characters or containing wildcards.

8. Filter values with invalid syntax.

In addition, performance testing should be done according to section _Success Metrics_.


Risks and Assumptions
---------------------

In order to write a filter value, a thorough analysis of the services implemented by installed security providers is expected. While providers document all service types and algorithms supported —so application developers can benefit from them—, this information is not necessarily available in a single standard or repository. Moreover, providers may name the same algorithms slightly differently, define their own aliases, support different cipher transformation modes and paddings or implement services that depend on other services to be available. When a security provider library is updated, new services may be offered, existing services modified and legacy services removed. As a result, filter values should be tailored to each environment after a comprehensive analysis and validated with adequate testing. Extrapolating filter values to other JDK deployments without a rigorous assessment may pose a risk for policy compliance.

The language proposed for filters pursues expressiveness power but inherits some of the low-level complexities of pattern languages and brings additional ones. These complexities include pseudo-regular expressions matching with greedy wildcards and character escape sequences, position-dependent patterns, allow and deny-list semantics, service aliases evaluation and special handling of cipher transformations. From all security configurations in OpenJDK, filters lean towards the advanced side and require expertise not only in their syntax and semantics but, more in general, in the Java Cryptographic Architecture. This proposal is an authoritative specification of a Security Providers Filter and is publicly available to address this concern. Extensive documentation about the JCA can be found in the Security Developer’s Guide.

The outcome of an incorrectly defined filter boils down to the following cases: 1) a service that should have been allowed was not, and 2) a service that should have been blocked was not. The first case is perhaps the less problematic, as the absence of a service may likely lead to broken or unavailable functionality detectable during application testing. The second case may compromise policy compliance and could be harder to notice. To mitigate these risks, this proposal includes filter debugging mechanisms and logs to help the filter writer understand the effects of a given value. These debugging mechanisms include log messages during filter parsing, log messages during services evaluation against the filter, exception messages pointing to syntactic errors and the listing of both allowed and blocked services for each installed provider. See more details about these mechanisms in section _Description_.

