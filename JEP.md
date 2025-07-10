Summary
-------

Extend the Java Cryptographic Architecture (JCA) with a runtime filtering mechanism to enable or disable security provider services.


Goals
-----

- Implement a filtering mechanism to constrain which security providers’ services are available for use in the `getInstance` JCA APIs.

- Apply the filter uniformly to both statically and dynamically installed OpenJDK and third-party providers.


Non-Goals
---------

- It is not a goal to standardize service names across OpenJDK and third-party providers.  The names used by the filter are based on the providers installed.

- It is not a goal to filter based on the calling class, package, module, or any algorithm parameters, such as key size, or `AlgorithmParameterSpec`.


Motivation
----------

Security providers offer a wide range of cryptographic services that can be accessed through JCA APIs such as Cipher and Signature. Given an algorithm, a service is selected based on a list of providers ordered by preference —potentially altered by the `jdk.security.provider.preferred` security property—, or by specifying the provider in the API invocation.

All services implemented by a provider are available to applications, regardless of whether their algorithm is cryptographically weak or non-compliant with a defined policy. The current mechanism misses the ability to block services by algorithm, service type or provider. While security properties exist to limit cryptographic algorithms in certain contexts —such as TLS, certificate path validation, and JAR signing—, these restrictions are only enforced at the implementation level and do not extend to every JCA API. Removing entire providers is not a viable solution, as services to be excluded might be bundled together with services required by an application. Selecting a provider for each API invocation might be possible in some cases but requires widespread code changes to the application and its dependencies, lacks flexibility, adds to the maintenance burden, and is less reliable due to the risk of overlooking a call site.

A filtering mechanism that blocks services across all JCA APIs would enable system administrators and application packagers to apply JDK-wide security and compliance policies. The list of policies that may be enforced includes security standards such as FIPS 140, performance policies to prevent the use of slow algorithms and policies to select algorithms based on interoperability.


Description
-----------

This proposal is for a configurable filter to enable or disable services implemented by security providers. The filter is initialized along with the providers classes, using the value of the `jdk.security.providers.filter` overridable security property. Once the filter is initialized, subsequent run time property updates do not cause a filter reset. When the filter property is not set or is set to the empty string, filtering is disabled. Each service is evaluated by the filter once in its lifetime, before use. A service that is rejected by the filter cannot be used in any of the JCA APIs, as if it were not implemented by its provider.

Filtering is enforced according to a multi-layer blocking strategy. Services are first filtered in `java.security.Provider` methods during registration. A second filter enforcement occurs in `java.security.Provider.Service::newInstance` to block unregistered services returned by special providers. In rare situations, a provider can override `::newInstance` and return an unvetted service implementation (SPI). Thus, a last layer of filtering is enforced in `::getInstance` JCA APIs.

Services are identifiable as a combination of a provider, a service type and an algorithm name. Optionally, an algorithm alias can be used in place of an algorithm name. A filter is made of a sequence of patterns that identify a service according to a matching criteria and indicate an action: allow or deny the service under evaluation.

The filter syntax is as follows:

`pattern-1; pattern-2; ...; pattern-n`

A service is evaluated against the filter from left to right. If a service matches one of the patterns in the sequence, a final authorization decision is made: if the pattern is prefixed by a `'!'` character (e.g. `! pattern-1`), the decision is to deny it; otherwise, the decision is to allow it. If none of the patterns match, the default decision is to deny the service. White spaces between patterns, pattern prefixes (`'!'`) and pattern separators (`';'`) are not significant.

Each pattern's syntax has one of the following forms:

1\. `provider`

2\. `provider.service-type`

3\. `provider.service-type.algorithm-or-alias`

In form \#1, a provider name equal to _provider_ is enough for a match to be successful. In form \#2, the service type must also be equal to _service-type_. In form \#3, the service algorithm or any of its aliases must also be equal to _algorithm-or-alias_. Cipher services require special handling as they might register multiple transformations under a single algorithm name, by means of the `SupportedModes` and `SupportedPaddings` attributes. When `Cipher.getInstance(transformation)` finds a service, a filter match is successful if _transformation_ or any of its aliases is equal to _algorithm-or-alias_ in form \#3. Pattern matching is always case insensitive.

Characters `'\n'` and `'\0'` are not valid in a pattern. The character `'.'` is used as a separator between different levels: provider, service type, algorithm name or alias. The following characters, when part of one of the listed levels, must be escaped by prepending a `'\'` character: `'!'`, `'*'`, `' '` (white space), `'.'`, `';'`, `'\'`, `':'` and `','`. Escaping any other character has no effect other than silently discarding the `'\'` character. Additionally, pattern names can contain `'*'` wildcards to imply zero or more repetitions of any character. Wildcards behave in greedy mode, trying to consume as many characters as possible and backing off if necessary.

The implementation of a service itself may require another service as a building block, either by invoking a JCA API or creating an instance of its implementation class directly. As a result, blocking a building block service may exhibit different behavior between providers. For example, blocking the service MessageDigest SHA256 may cause the service Signature SHA256withECDSA to stop working on a provider that obtained it through the JCA but does not affect one that creates an instance of its implementation class. If the service Signature SHA256withECDSA has to be blocked, the filter must have a rule for it.

For troubleshooting, it is possible to enable filter debugging logs with the System property `java.security.debug=jca` and look for messages prefixed by _ProvidersFilter_. To list services allowed and not allowed by a filter for each installed provider, run java with the argument `-XshowSettings:security:providers`. When a filter value is syntactically invalid, the exception message thrown points to the exact location in the pattern that could not be parsed.

### Examples of correctly defined filter values

Enable all security providers, service types and algorithms:

`jdk.security.providers.filter=`

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

### Examples of incorrectly defined filter values

Enable all services except for the HmacMD5 algorithm, irrespective of the security provider and the service type:

`jdk.security.providers.filter=*; !*.*.HmacMD5`

This is incorrect because the rule `"*"` matches and allows any service, while the rule blocking HmacMD5 is always ignored. The correct filter value for this example is `!*.*.HmacMD5; *`

--

Enable all services implemented by the SunPKCS11 security provider. Services implemented by other security providers should be disabled.

`jdk.security.providers.filter=SunPKCS11`

This is incorrect because the SunPKCS11 provider has to be identified by its name and not its class. A valid name would have the form of _SunPKCS11-SomeName_. A correct filter value for this example is `SunPKCS11-SomeName or SunPKCS11-*`


Alternatives
------------

### Filtering at the ::getInstance API level only

We explored simplifying the multi-layer filtering mechanism and applying the filter to `::getInstance` JCA APIs only. While this approach would require a thinner implementation, it lacks efficacy to block services under some circumstances. For example, an application may obtain a cipher service for an algorithm that should otherwise be blocked and instantiate its SPI (e.g. `provider.getService(...).newInstance(null)`). This SPI may be passed to a `javax.crypto.Cipher` constructor by means of subclass and be finally used. Removing the multi-layer would also weaken the effectiveness to block application-defined service types.

### Services shadowing

A mock provider would be installed first in order of preference. For service types and algorithms that have to be blocked, the mock provider would return services that, upon SPI instantiation, throw an unchecked exception. When a service has to be allowed, the mock provider does not return an instance and the fall back mechanism gets the service from the real provider (if available). This strategy can be combined with preferred algorithms for filtering based on the provider.

These are some of the drawbacks that have been identified for this variation:

- It would not be possible to block services when their security provider is passed as part of the JCA API invocation.

- Exceptions would be undocumented, making it difficult for applications to handle failures and looking for alternative services.

- Filtering based on the provider would require a comprehensive enumeration of all algorithms to be set as preferred.

### Services forwarding

Alternatively, the mock provider can impersonate all providers but keep references to the real provider internally. When a service is requested, the mock provider gets the service from the real provider, checks the filter and returns it wrapped in a service proxy.

These are some of the drawbacks that have been identified for this variation:

- The application can dynamically install a security provider high in order of preference rendering filtering ineffective.

- The filter is bypassed if a provider class instance is passed to a `::getInstance` API or one of its service SPIs used.

### Preferred algorithms only

In this alternative a new boolean Security property is introduced to optionally redefine the semantics of the existing `jdk.security.provider.preferred` property. With the new semantics, preferred services would be the only ones allowed.

These are some of the drawbacks that have been identified for this alternative:

- Overloaded property semantics may be confusing for users. There is no precedent for this type of behavior in a Security property.

- The current syntax for preferred services does not allow to include multiple services in a single rule nor a deny-list type of specification. This would make the filter highly verbose and error-prone. While the syntax can be extended, it would be difficult to do it in a way that is consistent and meaningful for both semantics.

### Alternative Filter syntaxes

The proposed filter syntax is inspired by existing Security properties such as the object serialization filter, the RMI Registry filter, the JNDI filters (global, LDAP and RMI) and the preferred providers list. While domain specific changes are needed to filter JCA services, many of the reserved characters and constructions retain their semantics: list of patterns ordered from left to right, separation of patterns by `';'`, use of `'!'` for rejection actions, availability of `'*'` wildcards for pattern matching, identification of services by `service-type.algorithm` patterns and the concept of matching all services when the service type or algorithm levels are not specified. The rationale behind this decision is to leverage on user familiarity with existing filtering grammars in OpenJDK and reduce the learning curve.

Nonetheless, alternative filter syntaxes have been explored. These efforts have gone in the direction of adding verbosity to patterns so filter components are explicit. For example, a pattern like `!SUN.MessageDigest.MD5; !*.MessageDigest.SHA*; *` could be expressed as

    { provider: SUN, service-type: MessageDigest, algorithm: MD5, decision: reject },
    { provider: ALL, service-type: MessageDigest, algorithm: { startsWith: SHA }, decision: reject },
    { provider: ALL, service-type: ALL, algorithm: ALL, decision: allow }

Virtually infinite variations and compromises between a highly compact and a fully verbose syntax can be laid out. However, they do not benefit from user familiarity with existing security filters and require more reserved words for an equivalent expressiveness power.


Testing
-------

Tests will include:

- Services filtering by security provider, service type, algorithm or alias.

- Filtering of Cipher services by transformation and transformation aliases.

- Filtering of services implemented by statically and dynamically installed security providers.

- Filtering of services implemented by providers that register services with the legacy API (i.e. `java.security.Provider::put`) or return unregistered services.

- Filtering in JCA APIs that pass a provider instance by parameter.

- Filter values requiring escaping of characters or containing wildcards.

- Filter values with invalid syntax.


Risks and Assumptions
---------------------

In order to write a filter value, a thorough analysis of the services implemented by installed security providers is expected. While there are [standard names](https://docs.oracle.com/en/java/javase/24/docs/specs/security/standard-names.html) for algorithms, providers might not follow this guideline or include non-standard algorithms. As a result, filter values should be tailored to each environment after a comprehensive analysis and validated with adequate testing. Extrapolating filter values to other JDK deployments without a rigorous assessment may pose a risk for policy compliance.

The language proposed for filters pursues expressiveness power but inherits some of the low-level complexities of pattern languages. These complexities include pseudo-regular expressions matching with greedy wildcards and character escape sequences, allow and deny-list semantics, and position-dependent patterns. From all security configurations in OpenJDK, filters lean towards the advanced side and require expertise not only in their syntax and semantics but, more in general, in the JCA. Extensive documentation about the JCA and the filter will be available in the Security Developer’s Guide.

The outcome of an incorrectly defined filter boils down to the following cases: 1) a service that should have been allowed was not, and 2) a service that should have been blocked was not. The first case is perhaps the less problematic, as the absence of a service may likely lead to broken or unavailable functionality detectable during application testing. The second case may compromise policy compliance and could be harder to notice. To mitigate these risks, this proposal includes filter debugging mechanisms and logs to help the filter writer understand the effects of a given value. See more details about these mechanisms in [_Description_](#Description).

