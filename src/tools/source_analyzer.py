"""Source Code Analyzer Tool - Multi-language vulnerability pattern detection."""
from __future__ import annotations

import re


def analyze_source_code(
    code: str,
    vulnerability_type: str = "sql_injection",
) -> dict:
    """
    Analyze source code for injection vulnerability patterns.

    Supports PHP, Python/Django/Flask, Node.js/Express, Java.
    vulnerability_type: sql_injection | command_injection | ssti |
                        nosql_injection | ldap_injection | xpath_injection |
                        crlf_injection | header_injection | path_traversal |
                        xss | ssrf | xxe
    """
    findings: dict = {
        "vulnerability_type": vulnerability_type,
        "patterns_found": [],
        "entry_points": [],
        "sinks": [],
        "potential_mitigations": [],
    }

    dispatch = {
        "sql_injection": _detect_sql_injection,
        "command_injection": _detect_command_injection,
        "ssti": _detect_ssti,
        "nosql_injection": _detect_nosql_injection,
        "ldap_injection": _detect_ldap_injection,
        "xpath_injection": _detect_xpath_injection,
        "crlf_injection": _detect_crlf_injection,
        "header_injection": _detect_crlf_injection,
        "path_traversal": _detect_path_traversal,
        "lfi": _detect_path_traversal,
        "file_inclusion": _detect_path_traversal,
        "xss": _detect_xss,
        "html_injection": _detect_xss,
        "ssrf": _detect_ssrf,
        "xxe": _detect_xxe,
        "xml_external_entity": _detect_xxe,
    }
    handler = dispatch.get(vulnerability_type.lower())
    if handler:
        handler(code, findings)

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match(code: str, patterns: list[tuple[str, str]], findings: dict, key: str) -> None:
    for pattern, description in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            findings[key].append(description)


def _entry_points(code: str, findings: dict, patterns: list[tuple[str, str]]) -> None:
    for pattern, label in patterns:
        for m in re.findall(pattern, code):
            findings["entry_points"].append(f"{label}: {m}")


def _sinks(code: str, findings: dict, patterns: list[tuple[str, str]]) -> None:
    for pattern, name in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            findings["sinks"].append(name)


# ---------------------------------------------------------------------------
# SQL Injection — PHP + Python/Django/Flask + Node.js + Java
# ---------------------------------------------------------------------------

def _detect_sql_injection(code: str, findings: dict) -> None:
    _match(code, [
        # PHP
        (r'mysqli_query\s*\(\s*\$[^,]+\s*,\s*["\'].*\$', "PHP: direct variable in mysqli_query"),
        (r'WHERE.*[=\s]+\$_(?:GET|POST|REQUEST)', "PHP: $_GET/POST in WHERE clause"),
        (r'(?:mysql_|mysqli_)query.*\$_(?:GET|POST|REQUEST)', "PHP: user input directly in SQL"),
        # Python / Django ORM
        (r'\.objects\.(?:filter|exclude|get)\s*\(.*%\s*request', "Django ORM: % formatting in queryset"),
        (r'\.objects\.(?:filter|exclude|get)\s*\(.*\.format\(', "Django ORM: str.format() in queryset"),
        (r'\.objects\.\w+\(.*\+\s*request\.', "Django ORM: concat with request input"),
        (r'\.order_by\s*\(\s*request\.', "Django: unsanitized order_by (CVE-2021-35042)"),
        (r'\.extra\s*\(.*request\.', "Django ORM: .extra() with user input"),
        (r'cursor\.execute\s*\(.*%\s*(?:request\.|params\[)', "Django: cursor.execute with % formatting"),
        (r'cursor\.execute\s*\(.*\+\s*(?:request\.|params\[)', "Django: cursor.execute with concat"),
        # Flask / SQLAlchemy
        (r'db\.engine\.execute\s*\(.*request\.(?:args|form)', "Flask: raw execute with request input"),
        (r'text\s*\(.*request\.(?:args|form)\.get', "SQLAlchemy text() with user input"),
        (r'session\.execute\s*\(.*\+\s*request\.', "SQLAlchemy: session.execute with concat"),
        # Node.js / Express
        (r'query\s*\(.*req\.(?:query|body|params)\.', "Node.js: db.query with req input"),
        (r'`.*\$\{req\.(?:query|body|params)\.', "Node.js: template literal SQL with req"),
        (r'"\s*\+\s*req\.(?:query|body|params)\.', "Node.js: string concat SQL with req"),
        # Java
        (r'Statement\.executeQuery\s*\(.*\+\s*request\.getParameter', "Java: JDBC concat with getParameter"),
        (r'createStatement\s*\(\s*\).*executeQuery', "Java: non-prepared Statement"),
        (r'prepareStatement.*\+.*getParameter', "Java: preparedStatement with concat"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'\$_GET\[[\'"](\w+)[\'"]\]', "PHP $_GET"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP $_POST"),
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.POST\.get\s*\([\'"](\w+)', "Django POST"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'request\.form\.get\s*\([\'"](\w+)', "Flask form"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'req\.body\.(\w+)', "Express body"),
        (r'req\.params\.(\w+)', "Express params"),
        (r'request\.getParameter\s*\([\'"](\w+)', "Java getParameter"),
    ])

    _sinks(code, findings, [
        (r'mysqli_query\s*\(', "mysqli_query()"),
        (r'cursor\.execute\s*\(', "cursor.execute()"),
        (r'db\.query\s*\(', "db.query()"),
        (r'Statement\.executeQuery\s*\(', "Statement.executeQuery()"),
        (r'\.order_by\s*\(', ".order_by()"),
        (r'\.extra\s*\(', ".extra()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Use parameterized queries / prepared statements",
            "Never pass raw user input to .extra() or .order_by()",
            "Whitelist allowed sort fields before calling order_by()",
        ]


# ---------------------------------------------------------------------------
# Command Injection — PHP + Python + Node.js + Java
# ---------------------------------------------------------------------------

def _detect_command_injection(code: str, findings: dict) -> None:
    _match(code, [
        # PHP
        (r'(?:system|exec|passthru|shell_exec)\s*\([^\)]*\$_(?:GET|POST|REQUEST)', "PHP: user input in OS command"),
        # Python
        (r'os\.system\s*\(.*request\.(?:GET|POST|args|form)', "Python: os.system with request input"),
        (r'subprocess\.(?:run|Popen|call)\s*\(.*request\.', "Python: subprocess with request input"),
        (r'os\.popen\s*\(.*request\.', "Python: os.popen with request input"),
        (r'subprocess\.(?:run|Popen|call)\s*\(.*shell\s*=\s*True', "Python: subprocess with shell=True"),
        # Node.js
        (r'child_process\.exec\s*\(.*req\.(?:query|body|params)\.', "Node.js: child_process.exec with req"),
        (r'exec\s*\(`.*\$\{req\.', "Node.js: exec template literal with req"),
        # Java
        (r'Runtime\.exec\s*\(.*request\.getParameter', "Java: Runtime.exec with getParameter"),
        (r'ProcessBuilder.*request\.getParameter', "Java: ProcessBuilder with getParameter"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'\$_GET\[[\'"](\w+)[\'"]\]', "PHP $_GET"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP $_POST"),
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'request\.getParameter\s*\([\'"](\w+)', "Java param"),
    ])

    _sinks(code, findings, [
        (r'os\.system\s*\(', "os.system()"),
        (r'subprocess\.(?:run|Popen|call)\s*\(', "subprocess()"),
        (r'child_process\.exec\s*\(', "child_process.exec()"),
        (r'Runtime\.exec\s*\(', "Runtime.exec()"),
        (r'system\s*\(', "system()"),
        (r'exec\s*\(', "exec()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Avoid shell=True in subprocess calls",
            "Use list-form commands instead of shell strings",
            "Validate and whitelist inputs before passing to OS commands",
        ]


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

def _detect_ssti(code: str, findings: dict) -> None:
    _match(code, [
        (r'render_template_string\s*\(.*request\.', "Flask: render_template_string with user input"),
        (r'render_template_string\s*\(.*\+', "Flask: render_template_string with concat"),
        (r'Environment\s*\(\s*\)\.from_string\s*\(.*request\.', "Jinja2 Environment.from_string with user input"),
        (r'Template\s*\(.*request\.', "Jinja2 Template() with user input"),
        (r'\{\{.*request\.', "Jinja2 tag with direct request interpolation"),
        (r'twig\.render\s*\(.*_GET|_POST', "Twig: render with user input"),
        (r'new\s+Template\s*\(.*req\.(?:query|body|params)\.', "Node.js: Template() with req input"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
    ])

    _sinks(code, findings, [
        (r'render_template_string\s*\(', "render_template_string()"),
        (r'Environment\s*\(\s*\)\.from_string\s*\(', "Environment().from_string()"),
        (r'Template\s*\(', "Template()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Never pass user input to render_template_string()",
            "Use render_template() with static filenames only",
            "Use SandboxedEnvironment from jinja2.sandbox",
        ]


# ---------------------------------------------------------------------------
# NoSQL Injection
# ---------------------------------------------------------------------------

def _detect_nosql_injection(code: str, findings: dict) -> None:
    _match(code, [
        (r'\.find\s*\(\s*\{.*request\.', "MongoDB: find() with request input"),
        (r'\.findOne\s*\(\s*\{.*request\.', "MongoDB: findOne() with request input"),
        (r'\$where.*request\.', "MongoDB: $where with user input"),
        (r'db\.\w+\.find\s*\(\s*req\.(?:query|body)', "Node.js MongoDB: find with req input"),
        (r'collection\.find\s*\(.*req\.', "Node.js: collection.find with req"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'req\.body\.(\w+)', "Express body"),
    ])

    _sinks(code, findings, [
        (r'\.find\s*\(', ".find()"),
        (r'\.findOne\s*\(', ".findOne()"),
        (r'\$where', "$where operator"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Strip $-prefixed keys from user-supplied objects",
            "Use Mongoose schema validation",
            "Avoid $where with user input",
        ]


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------

def _detect_ldap_injection(code: str, findings: dict) -> None:
    _match(code, [
        (r'ldap_search\s*\(.*\$_(?:GET|POST)', "PHP: ldap_search with user input"),
        (r'ldap3.*Connection.*request\.', "Python ldap3: search with request input"),
        (r'ldap\.search\s*\(.*request\.', "Python: ldap.search with request input"),
        (r'ActiveDirectory.*search.*request\.', "ActiveDirectory search with user input"),
        (r'ldapClient\.search\s*\(.*req\.(?:query|body)', "Node.js: ldap search with req"),
        (r'DirContext.*search.*getParameter', "Java JNDI: search with getParameter"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
    ])

    _sinks(code, findings, [
        (r'ldap_search\s*\(', "ldap_search()"),
        (r'ldap\.search\s*\(', "ldap.search()"),
        (r'ldapClient\.search\s*\(', "ldapClient.search()"),
        (r'DirContext.*search', "DirContext.search()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Escape special LDAP chars: * ( ) \\ NUL",
            "Use ldap3 escape_filter_chars() before building filter",
            "Whitelist valid input format",
        ]


# ---------------------------------------------------------------------------
# XPath Injection
# ---------------------------------------------------------------------------

def _detect_xpath_injection(code: str, findings: dict) -> None:
    _match(code, [
        (r'xpath\s*\(.*request\.', "XPath query with request input"),
        (r'etree.*xpath\s*\(.*request\.', "lxml etree XPath with request input"),
        (r'lxml.*xpath\s*\(.*request\.', "lxml XPath with request input"),
        (r'XPath\s*\(.*request\.', "XPath() with user input"),
        (r'selectNodes\s*\(.*req\.(?:query|body)', "Node.js: selectNodes with req"),
        (r'document\.evaluate\s*\(.*req\.', "JS: document.evaluate with req"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
    ])

    _sinks(code, findings, [
        (r'\.xpath\s*\(', ".xpath()"),
        (r'XPath\s*\(', "XPath()"),
        (r'selectNodes\s*\(', "selectNodes()"),
        (r'document\.evaluate\s*\(', "document.evaluate()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Use parameterized XPath queries",
            "Escape single quotes and parentheses in input",
            "Validate input against strict allowlist",
        ]


# ---------------------------------------------------------------------------
# CRLF / Header Injection
# ---------------------------------------------------------------------------

def _detect_crlf_injection(code: str, findings: dict) -> None:
    _match(code, [
        (r'(?:Location|Set-Cookie|Content-Type).*request\.', "Header value from request input"),
        (r'response\[.(?:Location|Set-Cookie)..\s*=.*request\.', "Direct request input in response header"),
        (r'redirect\s*\(.*request\.(?:GET|args|query)\.', "Redirect with unvalidated user input"),
        (r'res\.setHeader\s*\(.*req\.(?:query|body)', "Node.js: setHeader with req input"),
        (r'response\.headers\[.*\]\s*=.*request\.', "Python: response header from request"),
        (r'HttpResponse\s*\(.*getParameter', "Java: HttpResponse with getParameter"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'req\.query\.(\w+)', "Express query"),
    ])

    _sinks(code, findings, [
        (r'(?:Location|Set-Cookie)\s*:', "HTTP header (Location/Set-Cookie)"),
        (r'res\.setHeader\s*\(', "res.setHeader()"),
        (r'response\.headers\[', "response.headers[]"),
        (r'HttpServletResponse.*addHeader', "HttpServletResponse.addHeader()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Strip \\r and \\n from all user input used in headers",
            "Use framework redirect helpers that sanitize URLs",
            "Validate redirect targets against an allowlist",
        ]


# ---------------------------------------------------------------------------
# Path Traversal / Local File Inclusion
# ---------------------------------------------------------------------------

def _detect_path_traversal(code: str, findings: dict) -> None:
    _match(code, [
        (r'send_file\s*\(.*request\.', "Flask: send_file with request-controlled path"),
        (r'send_from_directory\s*\(.*request\.', "Flask: send_from_directory with request input"),
        (r'FileResponse\s*\(.*request\.', "Django: FileResponse with request input"),
        (r'open\s*\(.*request\.(?:GET|POST|args|form)', "Python: open() with request input"),
        (r'path\.join\s*\(.*req\.(?:query|body|params)', "Node.js: path.join with request input"),
        (r'fs\.readFile\s*\(.*req\.(?:query|body|params)', "Node.js: fs.readFile with request input"),
        (r'(?:readfile|file_get_contents|include|require)\s*\(.*\$_(?:GET|POST|REQUEST)', "PHP: filesystem/include sink with request input"),
        (r'ZipFile\([^)]*\)\.extractall\s*\(', "Python: archive extraction without path validation"),
        (r'tarfile\.[^\\n]*extractall\s*\(', "Python: tar extractall without path validation"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'request\.form\.get\s*\([\'"](\w+)', "Flask form"),
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'req\.body\.(\w+)', "Express body"),
        (r'\$_GET\[[\'"](\w+)[\'"]\]', "PHP $_GET"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP $_POST"),
    ])

    _sinks(code, findings, [
        (r'send_file\s*\(', "send_file()"),
        (r'send_from_directory\s*\(', "send_from_directory()"),
        (r'FileResponse\s*\(', "FileResponse()"),
        (r'fs\.readFile\s*\(', "fs.readFile()"),
        (r'file_get_contents\s*\(', "file_get_contents()"),
        (r'(?:include|require)\s*\(', "include/require"),
        (r'extractall\s*\(', "archive extractall()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Resolve paths and enforce that the final path stays under an allowed base directory",
            "Reject absolute paths, traversal segments, and encoded separators",
            "Use framework safe file-serving helpers with strict allowlists",
        ]


# ---------------------------------------------------------------------------
# XSS / HTML Injection
# ---------------------------------------------------------------------------

def _detect_xss(code: str, findings: dict) -> None:
    _match(code, [
        (r'innerHTML\s*=.*(?:req\.|request\.)', "Client/server code assigns request input to innerHTML"),
        (r'document\.write\s*\(.*(?:req\.|request\.)', "document.write with request input"),
        (r'dangerouslySetInnerHTML\s*=', "React dangerouslySetInnerHTML used"),
        (r'v-html\s*=', "Vue v-html sink"),
        (r'\|\s*safe\b', "Template output marked safe"),
        (r'Markup\s*\(.*request\.', "Flask/Jinja Markup with request input"),
        (r'res\.send\s*\(.*req\.(?:query|body|params)', "Express res.send with request input"),
        (r'echo\s+\$_(?:GET|POST|REQUEST)', "PHP echo of request input"),
        (r'print\s*\(.*request\.(?:GET|POST|args|form)', "Python print/render of request input"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'request\.form\.get\s*\([\'"](\w+)', "Flask form"),
        (r'request\.GET\.get\s*\([\'"](\w+)', "Django GET"),
        (r'request\.POST\.get\s*\([\'"](\w+)', "Django POST"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'req\.body\.(\w+)', "Express body"),
        (r'\$_GET\[[\'"](\w+)[\'"]\]', "PHP $_GET"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP $_POST"),
    ])

    _sinks(code, findings, [
        (r'innerHTML', "innerHTML"),
        (r'document\.write\s*\(', "document.write()"),
        (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML"),
        (r'v-html', "v-html"),
        (r'Markup\s*\(', "Markup()"),
        (r'res\.send\s*\(', "res.send()"),
        (r'echo\s+', "echo"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Contextually encode output before rendering HTML, attributes, URLs, or JavaScript",
            "Avoid safe/Markup/dangerouslySetInnerHTML for user content",
            "Sanitize rich text with a maintained allowlist sanitizer",
        ]


# ---------------------------------------------------------------------------
# Server-Side Request Forgery
# ---------------------------------------------------------------------------

def _detect_ssrf(code: str, findings: dict) -> None:
    _match(code, [
        (r'requests\.(?:get|post|request)\s*\(.*request\.(?:args|form|json)', "Python requests call with request URL input"),
        (r'urllib\.request\.urlopen\s*\(.*request\.', "Python urllib urlopen with request input"),
        (r'curl_exec\s*\(.*\$_(?:GET|POST|REQUEST)', "PHP curl_exec with request input"),
        (r'axios\.(?:get|post|request)\s*\(.*req\.(?:query|body|params)', "Node.js axios with request input"),
        (r'fetch\s*\(.*req\.(?:query|body|params)', "Node.js fetch with request input"),
        (r'http\.Get\s*\(.*r\.URL\.Query', "Go http.Get with query input"),
        (r'Net::HTTP\.get\s*\(.*params', "Ruby Net::HTTP with params"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.args\.get\s*\([\'"](\w+)', "Flask args"),
        (r'request\.form\.get\s*\([\'"](\w+)', "Flask form"),
        (r'req\.query\.(\w+)', "Express query"),
        (r'req\.body\.(\w+)', "Express body"),
        (r'\$_GET\[[\'"](\w+)[\'"]\]', "PHP $_GET"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP $_POST"),
    ])

    _sinks(code, findings, [
        (r'requests\.(?:get|post|request)\s*\(', "requests HTTP client"),
        (r'urlopen\s*\(', "urlopen()"),
        (r'curl_exec\s*\(', "curl_exec()"),
        (r'axios\.(?:get|post|request)\s*\(', "axios HTTP client"),
        (r'fetch\s*\(', "fetch()"),
        (r'http\.Get\s*\(', "http.Get()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Use an allowlist of outbound hosts and schemes",
            "Resolve DNS and block private, loopback, link-local, and metadata IP ranges",
            "Disable redirects or re-validate each redirect target",
        ]


# ---------------------------------------------------------------------------
# XML External Entity Injection
# ---------------------------------------------------------------------------

def _detect_xxe(code: str, findings: dict) -> None:
    _match(code, [
        (r'resolve_entities\s*=\s*True', "lxml parser resolves external entities"),
        (r'load_dtd\s*=\s*True', "lxml parser loads DTDs"),
        (r'etree\.(?:parse|fromstring)\s*\(.*request\.', "lxml/etree parses request-controlled XML"),
        (r'DocumentBuilderFactory\.newInstance\s*\(', "Java DocumentBuilderFactory XML parser"),
        (r'SAXParserFactory\.newInstance\s*\(', "Java SAXParserFactory XML parser"),
        (r'simplexml_load_string\s*\(.*\$_(?:POST|REQUEST)', "PHP simplexml_load_string with request input"),
        (r'DOMDocument\s*\([^)]*\).*loadXML\s*\(.*\$_(?:POST|REQUEST)', "PHP DOMDocument loadXML with request input"),
        (r'xml2js\.parseString\s*\(.*req\.(?:body|query)', "Node.js xml2js parses request input"),
    ], findings, "patterns_found")

    _entry_points(code, findings, [
        (r'request\.data', "Flask raw body"),
        (r'request\.files\[[\'"](\w+)[\'"]\]', "Flask uploaded file"),
        (r'req\.body\.(\w+)', "Express body"),
        (r'req\.files\.(\w+)', "Express uploaded file"),
        (r'\$_FILES\[[\'"](\w+)[\'"]\]', "PHP uploaded file"),
        (r'\$_POST\[[\'"](\w+)[\'"]\]', "PHP POST"),
    ])

    _sinks(code, findings, [
        (r'etree\.(?:parse|fromstring)\s*\(', "lxml/etree parser"),
        (r'DocumentBuilderFactory', "DocumentBuilderFactory"),
        (r'SAXParserFactory', "SAXParserFactory"),
        (r'simplexml_load_string\s*\(', "simplexml_load_string()"),
        (r'DOMDocument', "DOMDocument"),
        (r'xml2js\.parseString\s*\(', "xml2js.parseString()"),
    ])

    if findings["patterns_found"]:
        findings["potential_mitigations"] = [
            "Disable DTD and external entity resolution",
            "Use hardened parser defaults such as defusedxml",
            "Reject XML uploads unless required and validate content type/size strictly",
        ]
