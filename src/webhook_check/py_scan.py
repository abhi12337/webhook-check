"""Static checks for Python webhook handlers (FastAPI / Starlette, Flask, Django / DRF).

Uses the standard `ast` module. Handlers are route functions (`@app.post`, `@app.route(...,
methods=["POST"])`, `@router.api_route`, `add_url_rule`, Django views marked `@csrf_exempt`
/ `@require_POST` / `@api_view(["POST"])`, class-based `post()` methods) and any other
function that reads the request body and clearly handles a provider's webhook."""

from __future__ import annotations

import ast
import io
import re
import tokenize

from .findings import Finding, mask_secret, redact_line
from .handlers import Handler, classify, handler_findings
from .providers import GENERIC_VERIFY_RE

SECRET_NAME_RE = re.compile(
    r"(?i)(?:webhook|signing|endpoint|whsec|hmac|hook)\w*secret|secret\w*(?:webhook|signing|hmac|hook)|"
    r"(?:razorpay|rzp)\w*secret|twilio\w*auth_?token"
)
PLACEHOLDER_RE = re.compile(r"(?i)your|xxxx|\.\.\.|change|placeholder|example|dummy|replace|todo|insert|here|<|>|"
                            r"\{|\s|^whsec_x+$")
BENIGN_DECORATORS = re.compile(
    r"^(?:csrf_exempt|require_POST|require_GET|require_safe|require_http_methods|api_view|permission_classes|"
    r"authentication_classes|renderer_classes|parser_classes|throttle_classes|never_cache|atomic|"
    r"transaction\.atomic|staticmethod|classmethod|wraps|functools\.wraps|cross_origin|\w*limiter\.limit|limit|"
    r"exempt|csrf\.exempt|\w*\.exempt|method_decorator|retry|cache_control|vary_on_headers|swagger_auto_schema|"
    r"extend_schema|login_required|\w+\.(?:post|put|route|api_route|get|websocket))$"
)


def _views(text: str) -> tuple[list[str], list[str]]:
    """(clean_lines, code_lines): comments removed / additionally string contents blanked."""
    lines = text.splitlines(keepends=True)
    clean = [list(l) for l in lines]
    code = [list(l) for l in lines]
    fmid = getattr(tokenize, "FSTRING_MIDDLE", None)

    def blank(grid, start, end, keep_quotes):
        (sr, sc), (er, ec) = start, end
        for r in range(sr, er + 1):
            if r - 1 >= len(grid):
                break
            row = grid[r - 1]
            a = sc if r == sr else 0
            b = ec if r == er else len(row)
            for k in range(a, min(b, len(row))):
                if row[k] in "\r\n" or (keep_quotes and row[k] in "'\""):
                    continue
                row[k] = " "

    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                blank(clean, tok.start, tok.end, False)
                blank(code, tok.start, tok.end, False)
            elif tok.type == tokenize.STRING or (fmid is not None and tok.type == fmid):
                blank(code, tok.start, tok.end, True)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return ["".join(l).rstrip("\r\n") for l in clean], ["".join(l).rstrip("\r\n") for l in code]


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Await):
        return dotted(node.value)
    return ""


def _str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "encode":
        return _str(node.func.value)
    return None


def _strs(node: ast.AST | None) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [s for s in (_str(e) for e in node.elts) if s]
    s = _str(node)
    return [s] if s else []


def _arg(call: ast.Call, idx: int, *names: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg in names:
            return kw.value
    return call.args[idx] if len(call.args) > idx else None


def _walk_no_defs(nodes):
    stack = list(nodes)
    while stack:
        n = stack.pop()
        yield n
        for c in ast.iter_child_nodes(n):
            if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                stack.append(c)


class PyFile:
    def __init__(self, rel: str, text: str, tree: ast.Module):
        self.rel = rel
        self.text = text
        self.tree = tree
        self.lines = text.splitlines()
        self.clean, self.code = _views(text)
        self.clean_text = "\n".join(self.clean)
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self.secrets: list[str] = []
        imports = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imports |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.add(n.module.split(".")[0])
        self.imports = imports
        if imports & {"fastapi", "starlette"}:
            self.framework = "fastapi"
        elif imports & {"flask", "quart"}:
            self.framework = "flask"
        elif imports & {"django", "rest_framework"}:
            self.framework = "django"
        else:
            self.framework = "python"
        self.funcs: list[tuple[ast.AST, str | None]] = []      # (node, class name)
        self._collect(tree, None)
        self.top: dict[str, ast.AST] = {}
        for n, cls in self.funcs:
            if cls is None:
                self.top.setdefault(n.name, n)

    def _collect(self, node, cls):
        for c in ast.iter_child_nodes(node):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs.append((c, cls))
                self._collect(c, cls)
            elif isinstance(c, ast.ClassDef):
                self._collect(c, c.name)
            else:
                self._collect(c, cls)

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def add(self, rule: str, sev: str, msg: str, line: int, *, heuristic: bool = False, **extra) -> None:
        if (rule, line) in self._seen:
            return
        self._seen.add((rule, line))
        self.findings.append(Finding(rule, sev, msg, self.rel, line, redact_line(self.line_text(line), self.secrets),
                                     heuristic=heuristic,
                                     extra={"lang": "py", **{k: v for k, v in extra.items() if v is not None}}))

    def segment(self, fn, which: str = "clean") -> tuple[str, int]:
        first = min([d.lineno for d in fn.decorator_list] + [fn.lineno])
        src = self.clean if which == "clean" else self.code
        seg = src[first - 1:fn.end_lineno]
        if fn.lineno - first < len(seg):     # blank the function's own name
            i = fn.lineno - first
            seg = list(seg)
            seg[i] = re.sub(r"(\bdef\s+)" + re.escape(fn.name) + r"\b", lambda m: m.group(1) + "_" * len(fn.name),
                            seg[i], count=1)
        return "\n".join(seg), first


# ---------------------------------------------------------------- handler discovery
def _route_info(pf: PyFile, fn) -> tuple[bool, str | None, str, bool, list[str]]:
    """-> (is_route, path, framework, opaque, extra_names)"""
    is_route, path, fw, opaque, names = False, None, pf.framework, False, []
    for d in fn.decorator_list:
        dn = dotted(d)
        last = dn.rsplit(".", 1)[-1]
        if isinstance(d, ast.Call):
            if last in ("post", "put") and "." in dn and _str(d.args[0] if d.args else None) is not None:
                is_route, path = True, _str(d.args[0])
                fw = pf.framework if pf.framework != "python" else "fastapi"
                continue
            if last in ("route", "api_route") and "." in dn:
                methods = [m.upper() for m in _strs(_arg(d, 99, "methods"))]
                if "POST" in methods:
                    is_route, path = True, _str(d.args[0] if d.args else None)
                    fw = pf.framework if pf.framework != "python" else "flask"
                continue
            if last in ("require_http_methods", "api_view"):
                if "POST" in [m.upper() for m in _strs(d.args[0] if d.args else None)]:
                    is_route, fw = True, "django"
                continue
        if last in ("csrf_exempt", "require_POST"):
            is_route, fw = True, "django"
            continue
        if BENIGN_DECORATORS.match(dn) or BENIGN_DECORATORS.match(last):
            continue
        if GENERIC_VERIFY_RE.search(last + "("):
            names.append(last + "()")
            continue
        opaque = True
    return is_route, path, fw, opaque, names


def _registered_views(pf: PyFile) -> dict[str, str | None]:
    """Functions registered with app.add_url_rule / add_api_route with POST."""
    out: dict[str, str | None] = {}
    for n in ast.walk(pf.tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr in ("add_url_rule", "add_api_route", "add_route"):
            methods = [m.upper() for m in _strs(_arg(n, 99, "methods"))]
            view = _arg(n, 2 if n.func.attr == "add_url_rule" else 1, "view_func", "endpoint")
            if isinstance(view, ast.Call):
                view = view.args[0] if view.args else None
            name = dotted(view) if view is not None else ""
            if name and ("POST" in methods or n.func.attr == "add_route"):
                out[name.rsplit(".", 1)[-1]] = _str(n.args[0] if n.args else None)
    return out


def _helpers(pf: PyFile, fn, cls: str | None, depth: int = 0, seen: set[int] | None = None) -> list[ast.AST]:
    seen = seen if seen is not None else {id(fn)}
    out = []
    if depth >= 2:
        return out
    for n in _walk_no_defs(fn.body):
        if isinstance(n, ast.Call):
            target = None
            if isinstance(n.func, ast.Name):
                target = pf.top.get(n.func.id)
            elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and \
                    n.func.value.id in ("self", "cls"):
                target = next((f for f, c in pf.funcs if c == cls and f.name == n.func.attr), None)
            if target is not None and id(target) not in seen:
                seen.add(id(target))
                out.append(target)
                out.extend(_helpers(pf, target, cls, depth + 1, seen))
    return out


def find_handlers(pf: PyFile) -> list[Handler]:
    registered = _registered_views(pf)
    handlers: list[Handler] = []
    claimed: list[tuple[int, int]] = []
    candidates = []
    for fn, cls in pf.funcs:
        is_route, path, fw, opaque, names = _route_info(pf, fn)
        if fn.name in registered and cls is None:
            is_route, path = True, registered[fn.name]
            fw = pf.framework if pf.framework != "python" else "flask"
        if cls is not None and fn.name == "post":
            cdef = next((c for c in ast.walk(pf.tree) if isinstance(c, ast.ClassDef) and c.name == cls), None)
            bases = [dotted(b) for b in cdef.bases] if cdef else []
            if any(re.search(r"View|Resource|Endpoint|Handler", b) for b in bases):
                is_route, fw = True, pf.framework if pf.framework != "python" else "django"
        candidates.append((fn, cls, is_route, path, fw, opaque, names))
    # explicit routes first, then other functions (outermost first)
    candidates.sort(key=lambda c: (not c[2], -(c[0].end_lineno - c[0].lineno)))
    for fn, cls, is_route, path, fw, opaque, names in candidates:
        if not is_route and any(a <= fn.lineno <= b for a, b in claimed):
            continue
        own, first = pf.segment(fn, "clean")
        own_code, _ = pf.segment(fn, "code")
        helpers = _helpers(pf, fn, cls)
        hc = "\n".join(pf.segment(h, "clean")[0] for h in helpers)
        hk = "\n".join(pf.segment(h, "code")[0] for h in helpers)
        qual = f"{cls}.{fn.name}" if cls else fn.name
        label = f"POST {path}" if path else f"{qual}()"
        decl_line = first if is_route and path and fn.decorator_list else fn.lineno
        h = Handler(file=pf.rel, line=decl_line, lang="py", framework=fw if is_route else pf.framework, label=label,
                    route=path or (qual if is_route else None), explicit=is_route, own=own,
                    context=own + "\n" + hc + "\n" + " ".join(names), context_code=own_code + "\n" + hk + "\n" +
                    " ".join(names), own_start_line=first, lines=pf.lines, opaque=opaque)
        classify(h, pf.clean_text)
        if h.kind is None:
            continue
        handlers.append(h)
        claimed.append((fn.lineno, fn.end_lineno))
        for x in helpers:
            claimed.append((x.lineno, x.end_lineno))
    return handlers


# ---------------------------------------------------------------- file-level rules
def _payload_arg(pf: PyFile, call: ast.Call) -> tuple[ast.AST | None, str, str | None]:
    dn = dotted(call.func)
    last = dn.rsplit(".", 1)[-1]
    if last in ("construct_event", "verify_header"):
        return _arg(call, 0, "payload"), f"{dn}()", "stripe"
    if last == "verify_webhook_signature":
        return _arg(call, 0, "body"), f"{dn}()", "razorpay"
    if dn in ("hmac.new", "hmac.HMAC", "hmac.digest") or (last == "new" and dn == "new" and "hmac" in pf.imports):
        return _arg(call, 1, "msg"), f"{dn}()", None
    if last == "verify" and "svix" in pf.imports and isinstance(call.func, ast.Attribute):
        return _arg(call, 0, "payload", "data"), f"{dn}()", "svix"
    return None, "", None


def _taint_reason(node: ast.AST, tainted: dict[str, str]) -> str | None:
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            dn = dotted(n.func)
            if dn in ("json.dumps", "dumps", "orjson.dumps", "ujson.dumps", "simplejson.dumps"):
                return "json.dumps(...)"
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            dn = dotted(n.func)
            if dn in ("json.loads", "loads", "orjson.loads"):
                return "json.loads(...)"
            if dn.endswith(".get_json"):
                return "request.get_json()"
            if dn.endswith("request.json") or dn.endswith("req.json"):
                return "await request.json()"
            if dn.endswith(".model_dump") or dn.endswith(".dict"):
                return f"{dn}()"
        elif isinstance(n, ast.Attribute) and n.attr == "json" and dotted(n.value) in ("request", "req"):
            return "request.json"
        elif isinstance(n, ast.Name) and n.id in tainted:
            return tainted[n.id]
    return None


def check_raw_body(pf: PyFile) -> None:
    for fn, _ in pf.funcs:
        tainted: dict[str, str] = {}
        for _ in range(2):
            for n in _walk_no_defs(fn.body):
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    r = _taint_reason(n.value, tainted)
                    for t in targets:
                        if isinstance(t, ast.Name) and r:
                            tainted[t.id] = r
        for n in _walk_no_defs(fn.body):
            if not isinstance(n, ast.Call):
                continue
            payload, call, prov = _payload_arg(pf, n)
            if payload is None:
                continue
            reason = _taint_reason(payload, tainted)
            if not reason:
                continue
            label = {"stripe": "Stripe", "razorpay": "Razorpay", "svix": "Svix/Clerk"}.get(prov or "", "The webhook")
            if "dumps" in reason:
                msg = (f"{label} signature is checked in {call} against {reason} (re-serialized JSON), not the raw "
                       f"bytes that were signed: key order, spacing and unicode escapes differ, so real events fail "
                       f"and the check tends to get disabled.")
            else:
                msg = (f"{label} signature is checked in {call} against a parsed body ({reason}) instead of the raw "
                       f"request bytes: the signed bytes are already gone.")
            pf.add("WHK002", "high", msg, n.lineno, provider=prov, framework=pf.framework, call=call,
                   kind="stringify" if "dumps" in reason else "parsed")


def _digestish(n: ast.AST, digest_vars: set[str], hmac_vars: set[str]) -> str | None:
    if isinstance(n, ast.Name) and n.id in digest_vars:
        return n.id
    has_digest = has_hmac = False
    for x in ast.walk(n):
        if isinstance(x, ast.Call):
            dn = dotted(x.func)
            if dn.rsplit(".", 1)[-1] in ("hexdigest", "digest"):
                has_digest = True
            if dn in ("hmac.new", "hmac.digest", "hmac.HMAC") or (dn == "new" and "hmac" in dn):
                has_hmac = True
                if dn == "hmac.digest":
                    has_digest = True
        if isinstance(x, ast.Name) and (x.id in hmac_vars):
            has_hmac = True
        if isinstance(x, ast.Name) and x.id in digest_vars:
            return x.id
    return "HMAC digest" if has_digest and has_hmac else None


def check_compare(pf: PyFile) -> None:
    hmac_vars: set[str] = set()
    digest_vars: set[str] = set()
    assigns = [n for n in ast.walk(pf.tree) if isinstance(n, ast.Assign)]
    for n in assigns:
        if isinstance(n.value, ast.Call) and dotted(n.value.func) in ("hmac.new", "hmac.HMAC"):
            hmac_vars |= {t.id for t in n.targets if isinstance(t, ast.Name)}
    for _ in range(2):
        for n in assigns:
            if _digestish(n.value, digest_vars, hmac_vars):
                digest_vars |= {t.id for t in n.targets if isinstance(t, ast.Name)}
    if not digest_vars and not hmac_vars and "hmac" not in pf.imports:
        return
    for n in ast.walk(pf.tree):
        if not isinstance(n, ast.Compare) or len(n.ops) != 1 or not isinstance(n.ops[0], (ast.Eq, ast.NotEq)):
            continue
        left, right = n.left, n.comparators[0]
        d = _digestish(left, digest_vars, hmac_vars)
        other = right
        if not d:
            d = _digestish(right, digest_vars, hmac_vars)
            other = left
        if not d:
            continue
        if isinstance(other, ast.Constant) and (other.value in (None, "", b"", True, False, 0)):
            continue
        if isinstance(other, ast.Call) and dotted(other.func) == "len":
            continue
        op = "==" if isinstance(n.ops[0], ast.Eq) else "!="
        name = f"`{d}`" if d != "HMAC digest" else "the HMAC digest"
        pf.add("WHK003", "medium",
               f"HMAC signature {name} is compared with '{op}': a non-constant-time comparison leaks how much of a "
               f"forged signature is right (timing attack).", n.lineno, var=d, op=op, framework=pf.framework,
               other=ast.unparse(other) if len(ast.unparse(other)) <= 60 else None)


def _secret_call_arg(pf: PyFile, call: ast.Call) -> tuple[ast.AST | None, str]:
    dn = dotted(call.func)
    last = dn.rsplit(".", 1)[-1]
    if last in ("construct_event", "verify_header"):
        return _arg(call, 2, "secret"), f"{dn}()"
    if last == "verify_webhook_signature":
        return _arg(call, 2, "secret"), f"{dn}()"
    if dn in ("hmac.new", "hmac.HMAC", "hmac.digest"):
        return _arg(call, 0, "key"), f"{dn}()"
    if last == "Webhook" and "svix" in pf.imports:
        return _arg(call, 0, "whsecret", "secret"), "svix Webhook()"
    if last == "RequestValidator":
        return _arg(call, 0, "token"), "twilio RequestValidator()"
    return None, ""


def check_secrets(pf: PyFile) -> None:
    hits: dict[tuple[int, str], tuple[bool, str | None]] = {}

    def consider(node, where):
        v = _str(node)
        if v is None or len(v) < 8 or PLACEHOLDER_RE.search(v) or re.fullmatch(r"[A-Z][A-Z0-9_]+", v) or \
                len(set(v)) < 4:
            return
        whsec = v.startswith("whsec_") and len(v) >= 20
        if where is None and not whsec:
            return
        key = (node.lineno, v)
        if key not in hits or (hits[key][1] is None and where):
            hits[key] = (whsec, where)

    for n in ast.walk(pf.tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
                if name and SECRET_NAME_RE.search(name):
                    consider(n.value, f"in {name}")
        elif isinstance(n, ast.keyword) and n.arg and SECRET_NAME_RE.search(n.arg):
            consider(n.value, f"in {n.arg}=")
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                ks = _str(k) if k is not None else None
                if ks and SECRET_NAME_RE.search(ks):
                    consider(v, f"in {ks!r}")
        elif isinstance(n, ast.Call):
            dn = dotted(n.func)
            if dn in ("os.environ.get", "os.getenv", "getenv", "environ.get", "config", "env", "env.str"):
                name = _str(n.args[0]) if n.args else None
                default = _arg(n, 1, "default")
                if name and SECRET_NAME_RE.search(name) and default is not None:
                    consider(default, f"as the default for {name}")
            node, what = _secret_call_arg(pf, n)
            if node is not None:
                consider(node, f"passed directly to {what}")
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("whsec_"):
            consider(n, None)
    pf.secrets.extend(v for _, v in hits)
    for (line, v), (whsec, where) in sorted(hits.items()):
        if whsec:
            msg = (f"Stripe/Svix webhook signing secret (whsec_) hard-coded{(' ' + where) if where else ''}: anyone "
                   f"with the source can sign forged events.")
        else:
            msg = f"Webhook signing secret hard-coded {where}: anyone with the source can sign forged events."
        var = re.sub(r"^(?:in|as the default for|passed directly to)\s+", "", where or "secret").strip("'=")
        pf.add("WHK004", "critical" if whsec else "high", msg + f" Value: {mask_secret(v)}.", line, var=var)


VERIFY_CALLS = {"construct_event", "verify_header", "verify_webhook_signature", "verify_payment_signature",
                "unmarshal"}
EXIT_CALLS = re.compile(r"(?:^|\.)(?:abort|exit|HttpResponseBadRequest|HttpResponseForbidden|HTTPException|"
                        r"PermissionDenied|SuspiciousOperation)$")


def check_swallowed(pf: PyFile) -> None:
    for fn, _ in [(pf.tree, None)] + pf.funcs:
        body = fn.body
        for n in _walk_no_defs(body):
            if isinstance(n, ast.Try):
                verify = None
                for x in _walk_no_defs(n.body):
                    if isinstance(x, ast.Call):
                        dn = dotted(x.func)
                        last = dn.rsplit(".", 1)[-1]
                        if last in VERIFY_CALLS or                                 (last == "verify" and ("svix" in pf.imports or
                                                       re.search(r"(?i)wh|webhook|svix|verifier", dn))) or                                 (last == "validate" and "RequestValidator" in pf.text) or                                 (GENERIC_VERIFY_RE.search(last + "(") and last not in ("new", "digest", "HMAC")):
                            verify = dn
                            break
                if not verify:
                    continue
                for h in n.handlers:
                    exits = False
                    for x in _walk_no_defs(h.body):
                        if isinstance(x, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                            exits = True
                        elif isinstance(x, ast.Call) and EXIT_CALLS.search(dotted(x.func)):
                            exits = True
                    if exits:
                        continue
                    # `event = None` in the except, checked right after
                    nulls = [t.id for x in h.body if isinstance(x, ast.Assign) and isinstance(x.value, ast.Constant)
                             and x.value.value in (None, False) for t in x.targets if isinstance(t, ast.Name)]
                    after = "\n".join(pf.code[n.end_lineno:n.end_lineno + 40])
                    if any(re.search(r"\bnot\s+" + v + r"\b|\b" + v + r"\s+is\s+None\b|\b" + v + r"\s*==\s*None",
                                     after) for v in nulls):
                        continue
                    fallback = any(isinstance(x, ast.Assign) and _taint_reason(x.value, {}) for x in h.body)
                    pf.add("WHK005", "high",
                           f"Signature verification failure ({verify}) is caught and the handler carries on: this "
                           f"except block neither returns nor raises" +
                           (", and it falls back to the unverified body" if fallback else "") +
                           ", so a forged event is processed anyway.", h.lineno, kind="catch",
                           framework=pf.framework)
            elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                dn = dotted(n.value.func)
                last = dn.rsplit(".", 1)[-1]
                if last == "compare_digest" or (last == "validate" and "RequestValidator" in pf.text) or \
                        last == "is_valid_signature":
                    pf.add("WHK005", "high",
                           f"The result of {dn}() is ignored: it returns False for a bad signature instead of "
                           f"raising, so this line verifies nothing.", n.lineno, kind="ignored", call=dn,
                           framework=pf.framework)


def _const_num(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant):
        if node.value is None:
            return 0.0
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return float(node.value)
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _const_num(node.operand)
        return -v if v is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
        a, b = _const_num(node.left), _const_num(node.right)
        if a is None or b is None:
            return None
        return a * b if isinstance(node.op, ast.Mult) else a + b
    if isinstance(node, ast.Call) and dotted(node.func) == "float" and node.args and _str(node.args[0]) in ("inf", "infinity"):
        return float("inf")
    if dotted(node) in ("sys.maxsize", "math.inf"):
        return float("inf")
    return None


def check_tolerance(pf: PyFile) -> None:
    for n in ast.walk(pf.tree):
        if not isinstance(n, ast.Call):
            continue
        last = dotted(n.func).rsplit(".", 1)[-1]
        if last not in ("construct_event", "verify_header"):
            continue
        t = _arg(n, 3, "tolerance")
        if t is None:
            continue
        v = _const_num(t)
        if v is None:
            continue
        src = ast.unparse(t) if hasattr(ast, "unparse") else "?"
        if v <= 0:
            desc = f"{src} (timestamp check disabled)"
        elif v > 600:
            desc = f"{src} = {int(v) if v != float('inf') else 'infinite'} seconds instead of the default 300"
        else:
            continue
        pf.add("WHK008", "low",
               f"Stripe signature tolerance is {desc}: a captured event (from logs or a proxy) can be replayed long "
               f"after it was sent.", t.lineno)


def parse_failure(exc: BaseException) -> str:
    if isinstance(exc, SyntaxError):
        return f"syntax error line {exc.lineno}" if exc.lineno else "syntax error"
    if isinstance(exc, RecursionError):
        return "too deeply nested to parse"
    return f"could not be parsed ({exc})"


def scan_python(rel: str, text: str, skipped: list[dict] | None = None) -> tuple[list[Finding], list[Handler]]:
    """Findings and handlers for one file. A file `ast` cannot parse yields nothing and, when
    `skipped` is given, is appended to it as {"path", "reason"} so it can be reported."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as e:
        if skipped is not None:
            skipped.append({"path": rel, "reason": parse_failure(e)})
        return [], []
    pf = PyFile(rel, text, tree)
    check_secrets(pf)
    handlers = find_handlers(pf)
    for h in handlers:
        pf.findings.extend(handler_findings(h, pf.secrets))
    check_raw_body(pf)
    check_compare(pf)
    check_swallowed(pf)
    check_tolerance(pf)
    return pf.findings, handlers
