"""Sink taxonomy — maps callee method-name substrings to vulnerability types.

The audit LLM gets the full Q4 callee list; this table gives a deterministic
pre-filter so the model knows WHICH callees to scrutinize and as what.
Avoids relying on the model's free-form sink recognition (high FP).

Each entry: vuln_type -> list of sink patterns (matched as case-insensitive
substring on the callee's simple name, e.g. 'executeQuery' matches
'PreparedStatement.executeQuery' / 'Statement.executeQuery').

Scope: webgoat-classic Java sinks. Extend as needed.
"""
from __future__ import annotations

SINK_TAXONOMY: dict[str, list[str]] = {
    # SQL injection
    "SQLi": [
        "executeQuery", "executeUpdate", "execute", "executeBatch",
        "createStatement", "prepareStatement",   # only dangerous if concatenated
        "nativeQuery",                            # JPA / @Query native
    ],
    # Command injection / RCE
    "RCE": [
        "Runtime.exec", "getRuntime",
        "ProcessBuilder", "start",               # ProcessBuilder.start
        "Process", "exec",
    ],
    # Deserialization
    "deserialization": [
        "readObject", "ObjectInputStream",
        "readUnshared", "XMLDecoder",
        "SnakeYaml", "loadAs",                   # yaml deserialization
        "Jackson", "readValue",                  # polymorphic deserialization
        "XStream", "fromXML",
    ],
    # SSRF
    "SSRF": [
        "openConnection", "openStream",
        "URL.openConnection",
        "HttpClient", "send", "exchange",
        "RestTemplate", "getForObject", "postForObject",
        "WebClient", "uri",                     # WebClient.uri(...)
        "OkHttpClient", "newCall",
        "HttpURLConnection", "getInputStream",
    ],
    # Path traversal / file ops
    "path-traversal": [
        "new File", "FileInputStream", "FileOutputStream",
        "FileReader", "FileWriter",
        "Files.read", "Files.write", "Files.newInputStream", "Files.newOutputStream",
        "Paths.get",                             # dangerous with user input
        "transferTo",                           # MultipartFile.transferTo
    ],
    # XXE
    "XXE": [
        "DocumentBuilder", "parse",
        "SAXParser", "SAXReader",
        "XMLReader", "StAXReader",
        "Unmarshaller", "unmarshal",
        "XPath", "evaluate",
    ],
    # Expression injection (SpEL / OGNL / MVEL / Groovy)
    "expression-injection": [
        "parseExpression",                       # SpelExpressionParser.parseExpression
        "getValue",                              # EvaluationContext.getValue
        "Ognl", "getValue", "setValue",
        "MVEL", "eval",
        "GroovyShell", "evaluate",
        "ScriptEngine", "eval",
    ],
    # XSS (output sink — write to response without escape)
    "XSS": [
        "getWriter", "println",
        "addHeader",                             # header injection variant
        "sendRedirect",                          # open redirect / CRLF
    ],
    # LDAP injection
    "LDAP-injection": [
        "search", "ctx.search",                  # DirContext.search
        "LdapTemplate", "search",
    ],
    # JNDI / class loading
    "JNDI": [
        "InitialContext", "lookup",
        "Context.lookup",
        "Class.forName",                         # classloading RCE vector
    ],
    # XPath injection
    "XPath-injection": [
        "XPathExpression", "evaluate",
        "XPathFactory", "newXPath",
    ],
}


def classify_sink(callee_simple_name: str) -> str | None:
    """Return the vuln_type whose patterns match the callee name, or None.

    Substring match is case-insensitive on the callee's simple (unqualified) name.
    First match wins (taxonomy dict order). Extend with priority ordering if needed.
    """
    if not callee_simple_name:
        return None
    name_lower = callee_simple_name.lower()
    for vuln_type, patterns in SINK_TAXONOMY.items():
        for pat in patterns:
            if pat.lower() in name_lower:
                return vuln_type
    return None


def match_sinks(callee_qualified_names: list[str]) -> dict[str, str]:
    """Given Q4's distinct callee qualified_names, return {callee_qualified: vuln_type}.

    Callees not matching any pattern are dropped (not dangerous by this taxonomy).
    """
    matched: dict[str, str] = {}
    for fqn in callee_qualified_names:
        # simple name = last segment after '.', strip generics/args
        simple = fqn.rsplit(".", 1)[-1] if "." in fqn else fqn
        simple = simple.split("(")[0].split("<")[0]
        vt = classify_sink(simple)
        if vt is not None:
            matched[fqn] = vt
    return matched
