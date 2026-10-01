# LIT 2025 - tabled

- CTF ID: `LIT-2025-TABLED`
- Category: `Web`
- Injection Family: `SQL Injection`
- Vuln Type: `SQL Injection / SSTI mix`
- Difficulty: `Medium` / level `3`
- Auth Required: `Likely no initial auth`
- Source: [`ctfs/LIT/2025/web/tabled`](source)
- GitHub: https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LIT/2025/web/tabled

## Research Summary

LIT 2025 / tabled: User-controlled data reaches a database query through string interpolation, dynamic query construction, or a custom sanitizer instead of strict parameter binding. Injection type is SQL Injection. Attack surface: unauthenticated web parameters, login/search forms, JSON bodies, or API query fields that feed database/query logic. Recommended strategy: Abuse SQL/table-name handling and/or template rendering to disclose the randomized flag table.

## Source Evidence

ctfs/LIT/2025/web/tabled/main.py:1 `from flask import Flask, request, redirect, url_for, render_template_string, session` | ctfs/LIT/2025/web/tabled/main.py:14 `c.execute('''CREATE TABLE IF NOT EXISTS users (` | ctfs/LIT/2025/web/tabled/main.py:21 `c.execute("CREATE TABLE IF NOT EXISTS " + randomstring + " (flag TEXT)")`

## Root Cause

User-controlled data reaches a database query through string interpolation, dynamic query construction, or a custom sanitizer instead of strict parameter binding.

## Exploit Strategy

Abuse SQL/table-name handling and/or template rendering to disclose the randomized flag table.

## Agent Task

Enumerate sqlite_master through injectable login/register fields, then use any template surface only if needed for output.

## Setup

```bash
cd source && python3 main.py
```
