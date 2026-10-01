# DawgCTF 2025 - 4spam

- CTF ID: `DAWGCTF-2025-4SPAM`
- Category: `Web`
- Injection Family: `Command Injection`
- Vuln Type: `Command Injection in image conversion`
- Difficulty: `Medium` / level `3`
- Auth Required: `No`
- Source: [`ctfs/DawgCTF/2025/web/4spam`](source)
- GitHub: https://github.com/sajjadium/ctf-archives/tree/main/ctfs/DawgCTF/2025/web/4spam

## Research Summary

DawgCTF 2025 / 4spam: User-controlled input reaches a shell/subprocess command boundary without strict argument separation or allowlisted parsing. Injection type is Command Injection. Attack surface: unauthenticated command-like input such as host, filename, terminal text, generator options, or service parameters. Recommended strategy: Manipulate upload filename/path or image processing input so exec() runs attacker-controlled shell tokens.

## Source Evidence

ctfs/DawgCTF/2025/web/4spam/4spam.php:25 `$db->exec("CREATE TABLE IF NOT EXISTS posts (` | ctfs/DawgCTF/2025/web/4spam/4spam.php:78 `exec("gs -dBATCH -dNOSAFER -dNODISPLAY -dNOPAUSE -sDEVICE=jpeg -dLastPage=1 -r100 -sOutputFile={$imageRel}_proc.jpg $imageRel");` | ctfs/DawgCTF/2025/web/4spam/4spam.php:79 `exec("convert {$imageRel}_proc.jpg -thumbnail 100x100^ -gravity center -extent 100x100 {$imageRel}_thumb.jpg");`

## Root Cause

User-controlled input reaches a shell/subprocess command boundary without strict argument separation or allowlisted parsing.

## Exploit Strategy

Manipulate upload filename/path or image processing input so exec() runs attacker-controlled shell tokens.

## Agent Task

Upload a file with a crafted name, observe generated command behavior, and get a local command-execution proof without relying on external callbacks.

## Setup

```bash
cd source && php -S 0.0.0.0:8000 4spam.php
```
