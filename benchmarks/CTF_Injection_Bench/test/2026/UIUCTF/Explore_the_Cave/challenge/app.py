import os
import sqlite3
from pathlib import Path

from flask import Flask, request, render_template_string

app = Flask(__name__)

DB_PATH = Path("/tmp/cave.db")
FLAG = os.environ.get("FLAG", "uiuctf{redacted}")


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()

    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()

    cur.execute("CREATE TABLE main_cave (item_count TEXT, item TEXT, description TEXT)")
    cur.execute("CREATE TABLE secret_opening (item TEXT, secret, description TEXT)")

    cur.executemany(
        "INSERT INTO main_cave VALUES (?, ?, ?)",
        [
            ("4", "potion of healing", "heals you for 50hp"),
            ("1", "rune of strength", "increases str by 4"),
            ("1", "shiny iron broadsword", "once used by the knights of old, somehow recently refurbished"),
            ("3", "wooden plank", "crafting material"),
            ("100", "golden coins", "used as currency in the kingdom"),
            ("1", "old book", "what forbidden knowledge could it have...?"),
        ],
    )

    cur.execute(
        "INSERT INTO secret_opening VALUES (?, ?, ?)",
        (
            "blue ocarina",
            FLAG,
            "the legendary flute known to bend spacetime itself...",
        ),
    )

    db.commit()
    db.close()


init_db()


@app.get("/")
def index():
    return """
    <h1>the guarded cave</h1>

    <p>The hero has defeated a powerful beast guarding a vast cave and wanders inside. <br> many treasures await here... </p>

    <form action="/search" method="GET">
        <input name="q" placeholder="search for specific loot..">
        <button type="submit">search!</button>
    </form>

    <p><i>the hero is in search of the legendary blue ocarina...</i></p>
    """


@app.get("/search")
def search():
    term = request.args.get("q", "")

    query = (
        "SELECT item_count, item, description FROM main_cave "
        f"WHERE item_count LIKE '%{term}%' "
        f"OR item LIKE '%{term}%' "
        f"OR description LIKE '%{term}%' "
        "ORDER BY item"
    )

    db = sqlite3.connect(DB_PATH)

    try:
        rows = db.execute(query).fetchall()
        error = None
    except sqlite3.Error as e:
        rows = []
        error = str(e)

    db.close()

    return render_template_string(
        """
        <h1>here's what you found:</h1>

        <form action="/search" method="GET">
            <input name="q" value="{{ term }}" placeholder="search for specific loot:">
            <button type="submit">search!</button>
        </form>

        {% if error %}
            <p><b>error:</b> {{ error }}</p>
        {% endif %}

        <h2>Results</h2>

        {% if rows %}
            <table border="1" cellpadding="6">
                <tr>
                    <th>item count</th>
                    <th>item</th>
                    <th>description</th>
                </tr>
                {% for row in rows %}
                    <tr>
                        <td>{{ row[0] }}</td>
                        <td>{{ row[1] }}</td>
                        <td>{{ row[2] }}</td>
                    </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>nothing but dust and your own musty self haha</p>
        {% endif %}

        <p><a href="/">back to cave entrance</a></p>
        """,
        term=term,
        rows=rows,
        error=error,
    )


@app.get("/healthz")
def healthz():
    return "ok"
