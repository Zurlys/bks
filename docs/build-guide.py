#!/usr/bin/env python3
"""Turn GUIDE.md into docs/guide.html for the website (make site), and
stamp every page's style.css / demo.js link with a hash of the file, so
browsers fetch a changed file instead of a cached old one.

Handles exactly the Markdown that GUIDE.md uses: headings, paragraphs, lists,
tables, fenced code, inline code, bold and links. Standard library only.
"""
import hashlib
import html
import os
import re

# Fixed paths next to this script: no input decides what is read or written.
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, os.pardir, "GUIDE.md")
DST = os.path.join(HERE, "guide.html")

ASSETS = ("style.css", "demo.js")


def stamp(name):
    with open(os.path.join(HERE, name), "rb") as f:
        return "%s?v=%s" % (name, hashlib.sha256(f.read()).hexdigest()[:10])


def stamp_links(text):
    for a in ASSETS:
        text = re.sub(r'(href|src)="%s(\?v=[0-9a-f]+)?"' % re.escape(a), lambda m, a=a: '%s="%s"' % (m.group(1), stamp(a)), text)
    return text


lines = open(SRC, encoding="utf-8").read().split("\n")


def slug(text):
    """GitHub's heading anchors, so the guide's own links keep working."""
    s = re.sub(r"[^\w\- ]", "", text.lower())
    return s.replace(" ", "-")


def inline(text):
    # Set code spans aside first, so bold and links may wrap them.
    codes = []

    def keep(m):
        codes.append("<code>" + html.escape(m.group(1).replace("\\|", "|")) + "</code>")
        return "\x00%d\x00" % (len(codes) - 1)

    text = re.sub(r"`([^`]+)`", keep, text)
    text = html.escape(text.replace("\\|", "|"), quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)

    def link(m):
        label, url = m.group(1), m.group(2)
        if url.endswith(".md") and "://" not in url:  # repo files live on GitHub
            url = "https://github.com/Zurlys/bks/blob/main/" + url
        return '<a href="%s">%s</a>' % (html.escape(url), label)

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, text)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], text)


def cells(row):
    row = row.strip().strip("|")
    return [c.strip() for c in re.split(r"(?<!\\)\|", row)]


body, i, title = [], 0, "Using bks"
while i < len(lines):
    line = lines[i]
    if line.startswith("```"):
        code = []
        i += 1
        while i < len(lines) and not lines[i].startswith("```"):
            code.append(lines[i])
            i += 1
        body.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
        i += 1
        continue
    m = re.match(r"(#{1,3}) (.*)", line)
    if m:
        level, text = len(m.group(1)), m.group(2)
        if level == 1:
            title = text
            body.append("<h1>%s</h1>" % inline(text))
        else:
            body.append('<h%d id="%s">%s</h%d>' % (level, slug(text), inline(text), level))
        i += 1
        continue
    if line.startswith("|"):
        rows = []
        while i < len(lines) and lines[i].startswith("|"):
            rows.append(lines[i])
            i += 1
        head, data = cells(rows[0]), [cells(r) for r in rows[2:]]
        t = ['<div class="table"><table><thead><tr>']
        t += ["<th>%s</th>" % inline(c) for c in head]
        t.append("</tr></thead><tbody>")
        for r in data:
            t.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in r) + "</tr>")
        t.append("</tbody></table></div>")
        body.append("".join(t))
        continue
    if re.match(r"\s*- ", line):
        items = []
        while i < len(lines) and re.match(r"\s*- ", lines[i]):
            indent = len(lines[i]) - len(lines[i].lstrip())
            items.append((indent, lines[i].strip()[2:]))
            i += 1
        out, depth = [], -1
        for indent, text in items:
            d = 1 if indent else 0
            while depth < d:
                out.append("<ul>")
                depth += 1
            while depth > d:
                out.append("</ul>")
                depth -= 1
            out.append("<li>%s</li>" % inline(text))
        out.append("</ul>" * (depth + 1))
        body.append("".join(out))
        continue
    if line.strip() == "":
        i += 1
        continue
    para = []
    while i < len(lines) and lines[i].strip() and not re.match(r"(#|\||```|\s*- )", lines[i]):
        para.append(lines[i].strip())
        i += 1
    body.append("<p>%s</p>" % inline(" ".join(para)))

page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
  <meta name="referrer" content="no-referrer">
  <title>%(title)s — bks</title>
  <meta name="description" content="How to use bks: finding and copying entries, adding and editing them, tags, one-time codes and every keyboard shortcut.">
  <meta name="color-scheme" content="light dark">
  <link rel="stylesheet" href="style.css">
  <link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%%3E%%3Crect width='32' height='32' rx='6' fill='%%231F2B46'/%%3E%%3Crect x='6' y='14' width='20' height='5' fill='%%23F5F7FA'/%%3E%%3C/svg%%3E">
</head>
<body>
<header class="band">
  <nav class="band-inner" aria-label="Site">
    <a class="home" href="./">bks</a>
    <a href="guide.html" aria-current="page">Guide</a>
    <a href="https://github.com/Zurlys/bks/releases">Releases</a>
    <a href="https://github.com/Zurlys/bks/blob/main/DESIGN.md">How it works</a>
    <a href="https://github.com/Zurlys/bks/blob/main/SECURITY.md">Security model</a>
    <a href="https://github.com/Zurlys/bks">Source</a>
  </nav>
</header>
<main class="guide">
<!-- generated from GUIDE.md by docs/build-guide.py: edit GUIDE.md, then run make site -->
%(body)s
</main>
<footer>
  <p>bks is open source under the <a href="https://github.com/Zurlys/bks/blob/main/LICENSE">MIT license</a>. This page loads nothing from anywhere else.</p>
</footer>
</body>
</html>
""" % {"title": html.escape(title), "body": "\n".join(body)}

open(DST, "w", encoding="utf-8").write(stamp_links(page))

index = os.path.join(HERE, "index.html")
with open(index, encoding="utf-8") as f:
    old = f.read()
new = stamp_links(old)
if new != old:
    with open(index, "w", encoding="utf-8") as f:
        f.write(new)
