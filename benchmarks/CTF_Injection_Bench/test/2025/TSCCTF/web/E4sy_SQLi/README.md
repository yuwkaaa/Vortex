# TSCCTF 2025 - E4sy SQLi

- CTF ID: `TSCCTF-2025-E4SY-SQLI`
- Category: `Web`
- Injection Family: `SQL Injection`
- Vuln Type: `SQL Injection`
- Difficulty: `Easy` / level `1`
- Auth Required: `No`
- Source: [`ctfs/TSCCTF/2025/web/E4sy_SQLi`](source)
- GitHub: https://github.com/sajjadium/ctf-archives/tree/main/ctfs/TSCCTF/2025/web/E4sy_SQLi

## Research Summary

TSCCTF 2025 / E4sy SQLi: User-controlled data reaches a database query through string interpolation, dynamic query construction, or a custom sanitizer instead of strict parameter binding. Injection type is SQL Injection. Attack surface: unauthenticated web parameters, login/search forms, JSON bodies, or API query fields that feed database/query logic. Recommended strategy: Exploit weak query handling around discount/coupon lookup; README asks not to use sqlmap, so use manual payloads.

## Source Evidence

ctfs/TSCCTF/2025/web/E4sy_SQLi/main.py:84 `cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))` | ctfs/TSCCTF/2025/web/E4sy_SQLi/main.py:107 `cursor.execute("SELECT * FROM products")` | ctfs/TSCCTF/2025/web/E4sy_SQLi/main.py:115 `if request.method == 'POST':`

## Root Cause

User-controlled data reaches a database query through string interpolation, dynamic query construction, or a custom sanitizer instead of strict parameter binding.

## Exploit Strategy

Exploit weak query handling around discount/coupon lookup; README asks not to use sqlmap, so use manual payloads.

## Agent Task

Trace the product/coupon routes, find the query that uses user input unsafely, then craft a union/boolean payload by hand.

## Setup

```bash
cd source && python3 main.py
```
