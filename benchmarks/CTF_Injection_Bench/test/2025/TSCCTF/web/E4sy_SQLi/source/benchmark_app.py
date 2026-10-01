from __future__ import annotations

import os
import sqlite3

from flask import Flask, request


app = Flask(__name__)


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE coupons (code TEXT, reward TEXT)")
    conn.execute("INSERT INTO coupons VALUES ('WELCOME10', '10 percent discount')")
    conn.execute("INSERT INTO coupons VALUES ('FLAGCOUPON', ?)", (os.getenv("FLAG", "flag{missing}"),))
    return conn


@app.route("/", methods=["GET", "POST"])
def coupon_lookup() -> str:
    if request.method == "GET":
        return """
        <h1>E4sy SQLi</h1>
        <form method="post">
          <input name="coupon" placeholder="coupon">
          <button type="submit">Apply</button>
        </form>
        """

    coupon = request.form.get("coupon", "")
    conn = _db()
    query = f"SELECT reward FROM coupons WHERE code = '{coupon}'"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return f"SQL error: {exc}", 500
    finally:
        conn.close()

    if not rows:
        return "Invalid coupon"
    return "<br>".join(str(row[0]) for row in rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
