#!/usr/bin/env python3
"""Writes the HTML5 named character references (lib/html/entities.txt) from
Python's html.entities: one per line, the name (with its ";" when it has
one) and the code points, in hex. Run it again only if the list changes:

    python3 scripts/html_entities.py
"""
import html.entities
import os

out = os.path.join(os.path.dirname(__file__), "..", "lib", "html", "entities.txt")
with open(out, "w") as f:
    for name in sorted(html.entities.html5):
        points = " ".join("%x" % ord(c) for c in html.entities.html5[name])
        f.write("%s %s\n" % (name, points))
