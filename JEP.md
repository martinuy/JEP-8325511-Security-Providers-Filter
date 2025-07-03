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

In form \#1, a provider name equal to _provider_ is enough for a match to be successful. In form \#2, the service type must also be equal to _service-type_. In form \#3, the service algorithm or any of its aliases must also be equal to _algorithm-or-alias_. Cipher services require special handling as they might register multiple transformations under a single algorithm name, by means of the `SupportedModes` and `SupportedPaddings` attributes. When `Cipher.getInstance(transformation)` finds a service, a filter match is successful if _transformation_ or any of its aliases is equal to _algorithm-or-alias_ in form \#3.

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

