"""A small JavaScript / TypeScript lexer (there is no JS parser in the standard library).

`lex()` returns two copies of the source with identical offsets: `clean` has comments
blanked, `code` additionally has string and template-literal contents blanked (template
`${...}` expressions are kept). Matching structure on `code` means patterns never fire
inside strings or comments; reading values (route paths, secrets) uses `clean`."""

from __future__ import annotations

import re

# ---------------------------------------------------------------- lexing
def lex(text: str) -> tuple[str, str]:
    """-> (clean, code), both the same length as text.
    clean: comments blanked.  code: comments blanked and string/template contents blanked
    (template `${...}` expressions kept)."""
    n = len(text)
    clean = list(text)
    code = list(text)
    i = 0
    tmpl_stack: list[int] = []      # brace depth at which a template ${ } returns to the template
    brace = 0
    prev_sig = ""                   # last significant char, for regex-literal detection

    def blank(lst, a, b):
        for k in range(a, b):
            if lst[k] != "\n":
                lst[k] = " "

    def template_from(start: int) -> int:
        """start points just after a backtick (or a closing } of ${}); returns index after end."""
        nonlocal brace
        j = start
        while j < n:
            c = text[j]
            if c == "\\":
                blank(code, j, min(j + 2, n))
                j += 2
                continue
            if c == "`":
                return j + 1
            if c == "$" and j + 1 < n and text[j + 1] == "{":
                tmpl_stack.append(brace)
                brace += 1
                return -(j + 2)     # negative = continue in code mode at this index
            blank(code, j, j + 1)
            j += 1
        return n

    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(clean, i, j)
            blank(code, i, j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(clean, i, j)
            blank(code, i, j)
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            blank(code, i + 1, min(j, n))
            i = j + 1
            prev_sig = c
            continue
        if c == "`":
            r = template_from(i + 1)
            if r < 0:
                i = -r
                prev_sig = "{"
            else:
                i = r
                prev_sig = "`"
            continue
        if c == "/" and (prev_sig == "" or prev_sig in "(,=:[!&|?{};+-*%<>~^" or
                         re.search(r"\b(return|typeof|case|in|of)\s*$", text[max(0, i - 8):i])):
            j = i + 1
            in_class = False
            while j < n and text[j] != "\n":
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            blank(code, i + 1, min(j, n))
            i = j + 1
            prev_sig = "/"
            continue
        if c == "{":
            brace += 1
        elif c == "}":
            brace -= 1
            if tmpl_stack and brace == tmpl_stack[-1]:
                tmpl_stack.pop()
                r = template_from(i + 1)
                if r < 0:
                    i = -r
                    prev_sig = "{"
                else:
                    i = r
                    prev_sig = "`"
                continue
        prev_sig = c
        i += 1
    return "".join(clean), "".join(code)


_OPEN = {"(": ")", "[": "]", "{": "}"}


def match_close(code: str, open_idx: int) -> int:
    """Index of the bracket closing code[open_idx]; len(code) if unbalanced."""
    depth = 0
    for j in range(open_idx, len(code)):
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return len(code)


def split_args(code: str, start: int, end: int) -> list[tuple[int, int]]:
    """Top-level comma-separated spans of code[start:end]."""
    out, depth, a = [], 0, start
    for j in range(start, end):
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append((a, j))
            a = j + 1
    if code[a:end].strip():
        out.append((a, end))
    return out
