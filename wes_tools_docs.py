"""
wes_tools_docs — shared in-tool documentation layer for the wes-tools fleet.

One function: register_howto(app, *, tool_name). Mounts a /howto route on
the Flask app that renders the tool's HOWTO.md as a styled HTML page.

Authoring contract: each tool ships a HOWTO.md next to its app.py. Markdown
content, structured top→bottom from manager-readable summary to engineer-
level deep dive. The shared template handles styling, TOC, and chrome so
every tool's /howto looks the same.

This file is the canonical source. Each tool directory holds a vendored
copy at the same filename, propagated by `scripts/sync_shared.sh`.
"""
from __future__ import annotations

from pathlib import Path

import markdown
from flask import Flask, render_template_string


_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ tool_name }} — How it works</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"/>
    <style>
        :root { font-size: 87.5%; }
        body { margin: 0; }
        main.container { max-width: 1100px; padding: 1rem 1.5rem 4rem; }
        .top-bar {
            display: flex; align-items: center; justify-content: space-between;
            gap: 0.75rem; padding: 0.9rem 0 0.75rem;
            border-bottom: 1px solid var(--pico-muted-border-color);
            margin-bottom: 1.25rem;
        }
        .top-bar h2 { margin: 0; font-size: 1.15em; }
        .top-bar .back {
            font-size: 0.85em; color: #1b6ca8; text-decoration: none;
            padding: 0.25rem 0.7rem; border-radius: 999px;
            border: 1px solid #cfe1ee; background: #f0f7fc;
        }
        .top-bar .back:hover { background: #e0f0fa; }
        .toc {
            background: #f9f9f9;
            border: 1px solid var(--pico-muted-border-color);
            border-radius: 6px;
            padding: 0.85rem 1.1rem;
            margin: 1rem 0 2rem;
            font-size: 0.88em;
        }
        .toc-title {
            margin: 0 0 0.5rem; font-size: 0.78em; text-transform: uppercase;
            letter-spacing: 0.05em; color: var(--pico-muted-color); font-weight: 600;
        }
        .toc ul { margin: 0; padding-left: 1.25rem; }
        .toc li { margin: 0.15rem 0; list-style: none; }
        .toc ul ul { padding-left: 1.25rem; margin: 0.15rem 0; }
        .toc a { text-decoration: none; color: #1b6ca8; }
        .toc a:hover { text-decoration: underline; }
        article h1 { font-size: 1.55em; margin: 1.4em 0 0.4em; }
        article h2 {
            font-size: 1.22em; margin: 2em 0 0.5em;
            padding-top: 0.6em; border-top: 1px solid var(--pico-muted-border-color);
        }
        article h3 { font-size: 1.05em; margin: 1.4em 0 0.4em; }
        article h1:first-child { margin-top: 0; }
        article > h2:first-of-type { border-top: none; padding-top: 0; margin-top: 1em; }
        article p { line-height: 1.55; }
        article code {
            background: #f4f4f4; padding: 0.05em 0.35em; border-radius: 3px;
            font-size: 0.9em; font-family: ui-monospace, Menlo, monospace;
        }
        article pre {
            background: #f6f8fa; padding: 0.85rem 1rem; border-radius: 6px;
            overflow-x: auto; font-size: 0.85em; border: 1px solid #eaeaea;
        }
        article pre code { background: transparent; padding: 0; font-size: inherit; }
        article table { font-size: 0.92em; margin: 0.5rem 0 1rem; }
        article table th, article table td { padding: 0.4rem 0.6rem; }
        article blockquote {
            border-left: 3px solid #cfd8dc; padding: 0.2rem 0 0.2rem 1rem;
            color: #555; margin: 0.8rem 0;
        }
        article hr { border: none; border-top: 1px solid var(--pico-muted-border-color); margin: 2rem 0; }
        article a { color: #1b6ca8; }
        footer {
            margin-top: 3rem; padding-top: 1rem;
            border-top: 1px solid var(--pico-muted-border-color);
            font-size: 0.82em; color: var(--pico-muted-color); text-align: center;
        }
    </style>
</head>
<body>
<main class="container">
    <div class="top-bar">
        <h2>{{ tool_name }} — How it works</h2>
        <a href="/" class="back">← Back to tool</a>
    </div>
    {% if toc %}<div class="toc"><div class="toc-title">On this page</div>{{ toc | safe }}</div>{% endif %}
    <article>
        {{ body | safe }}
    </article>
    <footer>
        {{ tool_name }} · in-tool docs · rendered from <code>HOWTO.md</code>
    </footer>
</main>
</body>
</html>
"""


def register_howto(app: Flask, *, tool_name: str, howto_filename: str = "HOWTO.md") -> None:
    """Mount /howto on this Flask app, rendering HOWTO.md as a styled page.

    The Markdown file is read fresh on every request — supports edit-and-
    refresh without redeploy during local dev. In production this is cheap
    (a few KB of disk read + a fast markdown render) so we don't bother
    caching.

    Inherits whatever auth gate the host app has wired up; if the app's
    before_request runs an OIDC enforcer that covers all routes, /howto
    is covered automatically.
    """
    @app.route("/howto")
    def howto():
        howto_path = Path(app.root_path) / howto_filename
        if not howto_path.exists():
            return (
                f"<h1>HOWTO.md not found</h1><p>Looked at: <code>{howto_path}</code></p>"
                f"<p>Each tool ships its own <code>{howto_filename}</code> next to <code>app.py</code>.</p>",
                500,
            )

        md_text = howto_path.read_text(encoding="utf-8")
        md = markdown.Markdown(
            extensions=["toc", "fenced_code", "tables", "sane_lists"],
            extension_configs={
                "toc": {
                    "anchorlink": True,
                    "permalink": False,
                    "marker": "",
                    "toc_depth": "2-3",
                },
            },
        )
        body_html = md.convert(md_text)
        toc_html = md.toc if md.toc and "<ul>" in md.toc else ""

        return render_template_string(
            _PAGE_TEMPLATE,
            tool_name=tool_name,
            body=body_html,
            toc=toc_html,
        )
