"""Static checks for Node / TypeScript webhook handlers.

Handlers are found as Next.js App Router `export async function POST` in app/**/route.ts,
Next.js pages/api default exports, `app.post("/path", ...)` style routes (Express, Hono,
Fastify, Koa routers), Fastify `route({ method: "POST" })`, NestJS `@Post()` methods, and
any other function that reads the request body and clearly handles a provider's webhook
(provider signature headers, verification calls, event types). Works on a lexed copy of
the source (see jslex) and follows calls into same-file helper functions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .findings import Finding, mask_secret, redact_line
from .handlers import Handler, classify, handler_findings
from .jslex import lex, match_close, split_args
from .providers import BY_KEY, GENERIC_VERIFY_RE

IDENT = r"[A-Za-z_$][\w$]*"
KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "await", "new", "typeof", "const", "let",
            "var", "async", "true", "false", "null", "undefined", "this", "of", "in", "instanceof", "else", "case",
            "default", "throw", "try", "delete", "void", "yield", "import", "export", "from", "as", "class",
            "super", "do", "with", "get", "set", "static", "constructor"}

RELEVANT_RE = re.compile(r"webhook|stripe|razorpay|svix|clerk|shopify|paddle|lemon|twilio|paypal|hub-signature|"
                         r"github-event|hmac|whsec_|signature|secret|auth_?token", re.I)

FRAMEWORK_IMPORTS = [
    ("nestjs", re.compile(r"""['"]@nestjs/(?:common|core)['"]""")),
    ("hono", re.compile(r"""['"]hono(?:/[\w-]+)?['"]""")),
    ("fastify", re.compile(r"""['"]fastify['"]|\bfastify\s*\.\s*(?:post|route|register)\b""")),
    ("express", re.compile(r"""['"]express['"]""")),
    ("koa", re.compile(r"""['"](?:koa|@koa/router|koa-router)['"]""")),
]
HTTP_CLIENTS = {"axios", "ky", "got", "superagent", "supertest", "request", "agent", "wretch", "$http"}
BENIGN_MW_RE = re.compile(
    r"^(?:(?:express|bodyParser|body_parser)\.\w+|json|raw|text|urlencoded|cors|helmet|morgan|compression|"
    r"cookieParser|multer|upload(?:\.\w+)?|asyncHandler|catchAsync|asyncWrapper|wrapAsync|tryCatch|catchErrors|"
    r"asyncMiddleware|withErrorHandler|errorHandler|rateLimit\w*|\w*[lL]imiter|logger|requestLogger|bodyLimit|"
    r"zValidator|validator|tsr)$"
)
APP_ROUTE_RE = re.compile(r"(?:^|/)app/(?:(.*)/)?route\.(?:ts|js|mts|mjs|tsx|jsx)$")
PAGES_API_RE = re.compile(r"(?:^|/)pages/api/(.+)\.(?:ts|js|mts|mjs|tsx|jsx)$")
VERCEL_API_RE = re.compile(r"(?:^|/)api/(.+)\.(?:ts|js|mts|mjs)$")

SECRET_NAME_RE = re.compile(
    r"(?i)(?:webhook|signing|endpoint|whsec|hmac|hook)[\w$]*secret|secret[\w$]*(?:webhook|signing|hmac|hook)|"
    r"(?:razorpay|rzp)[\w$]*secret|twilio[\w$]*auth_?token"
)
PLACEHOLDER_RE = re.compile(r"(?i)your|xxxx|\.\.\.|change|placeholder|example|dummy|replace|todo|insert|here|<|>|"
                            r"\$\{|\s|^whsec_x+$")


@dataclass
class Fn:
    name: str | None
    start: int        # declaration start (for line numbers)
    popen: int        # '(' of the parameter list (or start of the single param)
    bopen: int        # body start ('{' or first char of an expression body)
    bend: int         # index after the body


def stmt_end(code: str, i: int) -> int:
    """Index after the expression/statement starting at i (depth-aware)."""
    depth, n = 0, len(code)
    j = i
    while j < n:
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0 and c in ";,":
            return j
        elif depth == 0 and c == "\n":
            k = j + 1
            while k < n and code[k] in " \t\r\n":
                k += 1
            if k >= n or code[k] not in ".?:+-*/&|=)]}":
                prev = code[i:j].rstrip()
                if not prev.endswith(("=", "(", ",", "+", "-", "*", "/", "&&", "||", "?", ":", "=>", ".")):
                    return j
        j += 1
    return n


def _body_after_params(code: str, pclose: int, arrow: bool | None) -> tuple[int, int] | None:
    """After the ')' of a parameter list: (body_start, body_end) of a block or arrow body.
    arrow=True requires '=>', False forbids it, None allows both."""
    m = re.compile(r"\s*(?::[^{;=()]*?(?:<[^;{}]*>)?)?\s*(=>)?\s*").match(code, pclose + 1)
    if not m:
        return None
    k = m.end()
    has_arrow = bool(m.group(1))
    if (arrow is True and not has_arrow) or (arrow is False and has_arrow):
        return None
    if k < len(code) and code[k] == "{":
        return k, match_close(code, k) + 1
    if has_arrow:
        return k, stmt_end(code, k)
    return None


FUNC_KW_RE = re.compile(r"(?<![\w$.])function\b\s*\*?\s*(" + IDENT + r")?\s*(?:<[^>()]*>)?\s*\(")
ARROW_DECL_RE = re.compile(r"(?<![\w$.])(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*(?:async\s*)?"
                           r"(\(|" + IDENT + r"\s*=>)")
PROP_ARROW_RE = re.compile(r"(?<![\w$.])(" + IDENT + r")\s*:\s*(?:async\s*)?(\(|" + IDENT + r"\s*=>)")
METHOD_RE = re.compile(r"(?m)^[ \t]*(?:(?:public|private|protected|static|async|override|export|default)\s+)*"
                       r"(" + IDENT + r")\s*(?:<[^>()]*>)?\s*\(")
ASSIGN_NAME_RE = re.compile(r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*(?:async\s+)?$")


def find_functions(code: str) -> list[Fn]:
    fns: dict[int, Fn] = {}

    def add(name, start, popen, body):
        if body and popen not in fns:
            fns[popen] = Fn(name, start, popen, body[0], body[1])

    for m in FUNC_KW_RE.finditer(code):
        popen = m.end() - 1
        name = m.group(1)
        if not name:
            b = ASSIGN_NAME_RE.search(code[max(0, m.start() - 160):m.start()])
            name = b.group(1) if b else None
        add(name, m.start(), popen, _body_after_params(code, match_close(code, popen), False))
    for rx in (ARROW_DECL_RE, PROP_ARROW_RE):
        for m in rx.finditer(code):
            if m.group(1) in KEYWORDS:
                continue
            if m.group(2) == "(":
                popen = m.end() - 1
                add(m.group(1), m.start(), popen, _body_after_params(code, match_close(code, popen), True))
            else:
                popen = m.start(2)
                arrow = code.index("=>", popen)
                k = arrow + 2
                while k < len(code) and code[k] in " \t\r\n":
                    k += 1
                body = (k, match_close(code, k) + 1) if k < len(code) and code[k] == "{" else (k, stmt_end(code, k))
                add(m.group(1), m.start(), popen, body)
    for m in METHOD_RE.finditer(code):
        name = m.group(1)
        if name in KEYWORDS or name == "function":
            continue
        popen = m.end() - 1
        add(name, m.start(1), popen, _body_after_params(code, match_close(code, popen), False))
    return sorted(fns.values(), key=lambda f: f.popen)


class JsFile:
    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self.lines = text.splitlines()
        self.clean, self.code = lex(text)
        self.fns = find_functions(self.code)
        self.by_name: dict[str, list[Fn]] = {}
        for f in self.fns:
            if f.name:
                self.by_name.setdefault(f.name, []).append(f)
        self._nl = [i for i, c in enumerate(text) if c == "\n"]
        if APP_ROUTE_RE.search(rel):
            self.framework = "next-app"
        elif PAGES_API_RE.search(rel):
            self.framework = "next-pages"
        else:
            self.framework = next((fw for fw, rx in FRAMEWORK_IMPORTS if rx.search(self.clean)), "node")
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self.secrets: list[str] = []
        self.routes: list[tuple[int, int, str]] = []   # (start, end, route path) of route registrations

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self._nl)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._nl[mid] < off:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def add(self, rule: str, sev: str, msg: str, off: int, *, heuristic: bool = False, **extra) -> None:
        line = self.line_of(off)
        if (rule, line) in self._seen:
            return
        self._seen.add((rule, line))
        self.findings.append(Finding(rule, sev, msg, self.rel, line, redact_line(self.line_text(line), self.secrets),
                                     heuristic=heuristic,
                                     extra={"lang": "js", **{k: v for k, v in extra.items() if v is not None}}))

    def fn_at(self, off: int) -> Fn | None:
        """Innermost function containing off."""
        best = None
        for f in self.fns:
            if f.popen <= off < f.bend and (best is None or f.bend - f.popen < best.bend - best.popen):
                best = f
        return best

    def route_at(self, off: int) -> tuple[int, int, str] | None:
        for r in self.routes:
            if r[0] <= off < r[1]:
                return r
        return None


# ---------------------------------------------------------------- handler discovery
def _string_at(clean: str, i: int) -> str | None:
    while i < len(clean) and clean[i] in " \t\r\n":
        i += 1
    if i < len(clean) and clean[i] in "'\"`":
        q = clean[i]
        j = clean.find(q, i + 1)
        if j > 0:
            val = clean[i + 1:j]
            return None if "${" in val else val
    return None


def _callee(expr: str) -> str | None:
    m = re.match(r"\s*(?:new\s+)?([A-Za-z_$][\w$.]*)\s*(?:<[^>()]*>)?\s*\(", expr)
    return m.group(1) if m else None


def _is_inline_fn(expr: str) -> bool:
    s = expr.strip()
    return bool(re.match(r"(?:async\b\s*)?(?:function\b|\(|" + IDENT + r"\s*=>)", s)) and \
        ("=>" in s or s.startswith(("function", "async function")))


class _Builder:
    """Collects handler spans for a JsFile."""

    def __init__(self, jf: JsFile):
        self.jf = jf
        self.handlers: list[Handler] = []
        self.claimed: list[tuple[int, int]] = []

    def make(self, label: str, route: str | None, framework: str, decl_off: int, spans: list[tuple[int, int]],
             extra_text: str = "", opaque: bool = False, explicit: bool = True, self_fn: Fn | None = None) -> None:
        jf = self.jf
        own = "\n".join(jf.clean[a:b] for a, b in spans)
        own_code = "\n".join(jf.code[a:b] for a, b in spans)
        used: list[Fn] = []
        helper_clean, helper_code = self.helpers(own_code, exclude={id(self_fn)} if self_fn else set(), used=used)
        file_mw = self.file_middleware()
        h = Handler(
            file=jf.rel, line=jf.line_of(decl_off), lang="js", framework=framework, label=label, route=route,
            explicit=explicit, own=own, context=own + "\n" + helper_clean + "\n" + extra_text + "\n" + file_mw,
            context_code=own_code + "\n" + helper_code + "\n" + extra_text + "\n" + file_mw,
            own_start_line=jf.line_of(spans[0][0]) if spans else jf.line_of(decl_off), lines=jf.lines, opaque=opaque)
        self.handlers.append(h)
        for a, b in spans:
            self.claimed.append((a, b))
        for f in used:
            self.claimed.append((f.popen, f.bend))

    def helpers(self, code_text: str, exclude: set[int], depth: int = 0, seen: set[int] | None = None,
                used: list[Fn] | None = None) -> tuple[str, str]:
        jf = self.jf
        seen = seen if seen is not None else set(exclude)
        cl, co = [], []
        if depth >= 2:
            return "", ""
        names = set(re.findall(r"(?<![\w$.])(" + IDENT + r")\s*\(", code_text))
        names |= set(re.findall(r"\bthis\s*\.\s*(" + IDENT + r")\s*\(", code_text))
        # identifiers passed as callbacks: app.post("/x", handleWebhook)
        names |= set(re.findall(r"[,(]\s*(" + IDENT + r")\s*(?=[,)])", code_text))
        for n in sorted(names):
            if n in KEYWORDS:
                continue
            for f in jf.by_name.get(n, [])[:2]:
                if id(f) in seen:
                    continue
                seen.add(id(f))
                if used is not None:
                    used.append(f)
                cl.append(jf.clean[f.popen:f.bend])
                co.append(jf.code[f.popen:f.bend])
                c2, k2 = self.helpers(jf.code[f.popen:f.bend], exclude, depth + 1, seen, used)
                cl.append(c2)
                co.append(k2)
        return "\n".join(cl), "\n".join(co)

    _file_mw: str | None = None

    def file_middleware(self) -> str:
        """Names of app-level middleware / hooks, as calls, so verify-named ones count."""
        if self._file_mw is None:
            jf = self.jf
            names = []
            for m in re.finditer(r"\.\s*(?:use|addHook|register)\s*\(", jf.code):
                o = m.end() - 1
                c = match_close(jf.code, o)
                for n in re.findall(IDENT, jf.code[o + 1:c]):
                    if n not in KEYWORDS:
                        names.append(n + "()")
            self._file_mw = " ".join(names)
        return self._file_mw

    # -- argument list of a route registration: [middleware..., handler]
    def route_args(self, label: str, route: str | None, decl_off: int, args: list[tuple[int, int]],
                   framework: str) -> None:
        jf = self.jf
        if not args:
            return
        spans: list[tuple[int, int]] = []
        extra: list[str] = []
        opaque = False
        self_fn = None
        found = False
        for i, (a, b) in enumerate(args):
            expr = jf.code[a:b]
            s = expr.strip()
            last = i == len(args) - 1
            if s.startswith("{"):                 # fastify options / hono validator config
                extra.append(jf.clean[a:b])
                for n in re.findall(r"(?:preHandler|preValidation|onRequest|preParsing)\s*:\s*\[?\s*([\w$.,\s]+)", expr):
                    extra.extend(x.strip() + "()" for x in n.split(",") if x.strip())
                continue
            if _is_inline_fn(s):
                spans.append((a, b))
                found = True
                continue
            callee = _callee(s)
            if callee is not None:
                o = a + expr.index("(", expr.index(callee.split(".")[-1]))
                inner = jf.code[o + 1:match_close(jf.code, o)]
                if "=>" in inner or "function" in inner:   # wrapper(async (req, res) => {...})
                    spans.append((a, b))
                    found = True
                    if not BENIGN_MW_RE.match(callee) and not GENERIC_VERIFY_RE.search(callee + "("):
                        opaque = True
                    extra.append(callee + "()")
                    continue
                extra.append(callee + "()")
                if not BENIGN_MW_RE.match(callee) and not GENERIC_VERIFY_RE.search(callee + "("):
                    opaque = True
                continue
            if re.fullmatch(r"[A-Za-z_$][\w$.]*", s):
                name = s.split(".")[-1]
                if last:
                    fs = jf.by_name.get(name, [])
                    if len(fs) == 1:
                        f = fs[0]
                        spans.append((f.popen, f.bend))
                        self_fn = f
                        found = True
                    continue
                extra.append(s + "()")
                if not BENIGN_MW_RE.match(s) and not GENERIC_VERIFY_RE.search(name + "("):
                    opaque = True
        if found:
            self.make(label, route, framework, decl_off, spans, "\n".join(extra), opaque, True, self_fn)

    def find_express_style(self) -> None:
        jf = self.jf
        code, clean = jf.code, jf.clean
        if re.search(r"""['"]msw['"]""", clean):
            return
        rx = re.compile(r"(?<![\w$])((?:this\s*\.\s*)?" + IDENT + r")\s*\.\s*(post|all|put|route)\s*\(")
        chained_seen: set[int] = set()
        for m in rx.finditer(code):
            recv, method = m.group(1), m.group(2)
            if recv in HTTP_CLIENTS:
                continue
            o = m.end() - 1
            if o in chained_seen:
                continue
            c = match_close(code, o)
            args = split_args(code, o + 1, c)
            if not args:
                continue
            fw = jf.framework if jf.framework != "node" else "express"
            if method == "route":
                first = code[args[0][0]:args[0][1]].strip()
                if first.startswith("{"):             # fastify.route({ method: "POST", url, handler })
                    obj = clean[args[0][0]:args[0][1]]
                    if not re.search(r"""method\s*:\s*\[?[^\]}]*['"]POST['"]""", obj, re.I):
                        continue
                    um = re.search(r"""(?:url|path)\s*:\s*(['"])(.*?)\1""", obj)
                    route = um.group(2) if um else None
                    hm = re.search(r"\bhandler\s*:\s*", code[args[0][0]:args[0][1]])
                    if not hm:
                        continue
                    hs = args[0][0] + hm.end()
                    he = stmt_end(code, hs)
                    jf.routes.append((m.start(), c + 1, route or ""))
                    self.route_args(f"POST {route}" if route else "fastify route", route, m.start(),
                                    [(hs, he)], "fastify")
                    continue
                path = _string_at(clean, args[0][0])
                if path is None:
                    continue
                # express: router.route("/x").get(...).post(handler)
                k = c + 1
                while True:
                    cm = re.compile(r"\s*\.\s*(" + IDENT + r")\s*\(").match(code, k)
                    if not cm:
                        break
                    co = cm.end() - 1
                    cc = match_close(code, co)
                    chained_seen.add(co)
                    if cm.group(1) in ("post", "all"):
                        jf.routes.append((m.start(), cc + 1, path))
                        self.route_args(f"POST {path}", path, m.start(), split_args(code, co + 1, cc), fw)
                    k = cc + 1
                continue
            path = _string_at(clean, args[0][0])
            if path is None:
                continue
            jf.routes.append((m.start(), c + 1, path))
            self.route_args(f"{method.upper() if method != 'all' else 'POST'} {path}", path, m.start(), args[1:], fw)

    def find_next_app(self) -> None:
        jf = self.jf
        m = APP_ROUTE_RE.search(jf.rel)
        if not m:
            return
        segs = [s for s in (m.group(1) or "").split("/") if s and not (s.startswith("(") and s.endswith(")"))]
        segs = [s for s in segs if not s.startswith("@")]
        route = "/" + "/".join(segs)
        code = jf.code
        label = f"POST {route}"
        fm = re.search(r"export\s+(?:async\s+)?function\s+POST\s*(?:<[^>()]*>)?\s*\(", code)
        if fm:
            f = next((x for x in jf.fns if x.popen == fm.end() - 1), None)
            if f:
                self.make(label, route, "next-app", fm.start(), [(f.popen, f.bend)], self_fn=f)
            return
        cm = re.search(r"export\s+const\s+POST\s*(?::[^=]+)?=\s*", code)
        if cm:
            f = next((x for x in jf.fns if x.name == "POST" and x.start <= cm.start() + 20 and x.start >= cm.start()), None)
            if f:
                self.make(label, route, "next-app", cm.start(), [(f.popen, f.bend)], self_fn=f)
                return
            end = stmt_end(code, cm.end())
            self.route_args(label, route, cm.start(), [(cm.end(), end)], "next-app")
            return
        em = re.search(r"export\s*\{[^}]*\b(" + IDENT + r")\s+as\s+POST\b", code)
        if em:
            fs = jf.by_name.get(em.group(1), [])
            if len(fs) == 1:
                self.make(label, route, "next-app", fs[0].start, [(fs[0].popen, fs[0].bend)], self_fn=fs[0])

    def find_default_export(self) -> None:
        jf = self.jf
        pm = PAGES_API_RE.search(jf.rel)
        vm = VERCEL_API_RE.search(jf.rel) if not pm and not APP_ROUTE_RE.search(jf.rel) else None
        if not pm and not vm:
            return
        sub = (pm or vm).group(1)
        sub = re.sub(r"(?:^|/)index$", "", sub)
        route = "/api/" + sub if sub else "/api"
        fw = "next-pages" if pm else "node"
        label = f"POST {route}"
        code = jf.code
        dm = re.search(r"export\s+default\s+|module\.exports\s*=\s*", code)
        if not dm:
            return
        rest = code[dm.end():]
        if re.match(r"(?:async\s+)?function\b", rest):
            f = next((x for x in jf.fns if dm.end() <= x.start <= dm.end() + 20), None)
            if f:
                self.make(label, route, fw, dm.start(), [(f.popen, f.bend)], self_fn=f)
            return
        if re.match(r"(?:async\s*)?\(", rest):
            o = dm.end() + rest.index("(")
            body = _body_after_params(code, match_close(code, o), True)
            if body:
                self.make(label, route, fw, dm.start(), [(o, body[1])])
            return
        im = re.match(r"(" + IDENT + r")\s*(?:;|\n|$)", rest)
        if im:
            fs = jf.by_name.get(im.group(1), [])
            if len(fs) == 1:
                self.make(label, route, fw, fs[0].start, [(fs[0].popen, fs[0].bend)], self_fn=fs[0])
            return
        if _callee(rest):
            end = stmt_end(code, dm.end())
            self.route_args(label, route, dm.start(), [(dm.end(), end)], fw)

    def find_deno(self) -> None:
        """Deno.serve(handler) / serve(handler): Supabase Edge Functions, Deno Deploy."""
        jf = self.jf
        for m in re.finditer(r"(?<![\w$.])(?:Deno\s*\.\s*serve|serve)\s*\(", jf.code):
            o = m.end() - 1
            args = split_args(jf.code, o + 1, match_close(jf.code, o))
            if not args:
                continue
            fm = re.search(r"(?:^|/)supabase/functions/([^/]+)/", jf.rel)
            route = f"/functions/v1/{fm.group(1)}" if fm else None
            jf.routes.append((m.start(), match_close(jf.code, o) + 1, route or ""))
            self.route_args(f"POST {route}" if route else "Deno.serve handler", route, m.start(), args[-1:], "deno")

    def find_nest(self) -> None:
        jf = self.jf
        if jf.framework != "nestjs":
            return
        pre = re.search(r"""@Controller\(\s*(['"])(.*?)\1""", jf.clean)
        prefix = pre.group(2).strip("/") if pre else ""
        for m in re.finditer(r"@Post\s*\(", jf.code):
            o = m.end() - 1
            c = match_close(jf.code, o)
            path = (_string_at(jf.clean, o + 1) or "").strip("/")
            route = "/" + "/".join(x for x in (prefix, path) if x)
            f = next((x for x in jf.fns if x.popen > c and x.start > c), None)
            if f:
                self.make(f"POST {route}", route, "nestjs", m.start(), [(f.popen, f.bend)], self_fn=f)

    def find_plain_functions(self) -> None:
        """Functions that are not registered routes here but clearly handle a webhook request
        (controllers in another file, Lambda / Netlify / Workers handlers)."""
        jf = self.jf
        for f in sorted(jf.fns, key=lambda x: -(x.bend - x.popen)):
            if any(a <= f.popen < b for a, b in self.claimed):
                continue
            if not f.name and f.bend - f.popen < 40:
                continue
            label = f"{f.name}()" if f.name else "anonymous function"
            n_claimed = len(self.claimed)
            self.make(label, None, jf.framework, f.start, [(f.popen, f.bend)], explicit=False, self_fn=f)
            h = self.handlers[-1]
            classify(h, jf.clean)
            if h.kind is None:
                self.handlers.pop()
                del self.claimed[n_claimed:]


# ---------------------------------------------------------------- file-level rules
def _arg(code: str, open_idx: int, n: int) -> tuple[int, int] | None:
    args = split_args(code, open_idx + 1, match_close(code, open_idx))
    return args[n] if len(args) > n else None


PAYLOAD_CALLS = [
    (re.compile(r"(?<![\w$])constructEvent(?:Async)?\s*\("), 0, "stripe", "stripe.webhooks.constructEvent()"),
    (re.compile(r"(?<![\w$])validateWebhookSignature\s*\("), 0, "razorpay", "validateWebhookSignature()"),
    (re.compile(r"\.\s*unmarshal\s*\("), 0, "paddle", "paddle.webhooks.unmarshal()"),
    (re.compile(r"\bsubtle\s*\.\s*sign\s*\("), 2, None, "crypto.subtle.sign()"),
    (re.compile(r"\bsubtle\s*\.\s*verify\s*\("), 3, None, "crypto.subtle.verify()"),
]
VERIFY_LIB_RE = re.compile(r"""['"](?:svix|@octokit/webhooks|standardwebhooks|@octokit/webhooks-methods)['"]""")


def _provider_hint(jf: JsFile, off: int, default: str | None) -> str | None:
    if default:
        return default
    window = jf.clean[max(0, off - 1500):off + 500]
    for key, rx in (("github", r"x-hub-signature"), ("shopify", r"x-shopify-hmac"), ("razorpay", r"razorpay"),
                    ("lemonsqueezy", r"x-signature|lemon"), ("paddle", r"paddle"), ("svix", r"svix|clerk"),
                    ("stripe", r"stripe")):
        if re.search(rx, window, re.I):
            return key
    return None


def _payload_sites(jf: JsFile):
    code = jf.code
    for rx, idx, prov, call in PAYLOAD_CALLS:
        for m in rx.finditer(code):
            a = _arg(code, m.end() - 1, idx)
            if a:
                yield m.start(), a, _provider_hint(jf, m.start(), prov), call
    if VERIFY_LIB_RE.search(jf.clean):
        for m in re.finditer(r"(?<![\w$])(" + IDENT + r")\s*\.\s*verify\s*\(", code):
            if m.group(1) in ("jwt", "jose", "crypto", "bcrypt", "argon2"):
                continue
            a = _arg(code, m.end() - 1, 0)
            if a:
                prov = "github" if "@octokit" in jf.clean else "svix"
                yield m.start(), a, prov, f"{m.group(1)}.verify()"
    for m in re.finditer(r"\bcreateHmac\s*\(", code):
        c = match_close(code, m.end() - 1)
        um = re.compile(r"\s*\.\s*update\s*\(").match(code, c + 1)
        if um:
            a = _arg(code, um.end() - 1, 0)
            if a:
                at = um.start() + len(code[um.start():um.end()]) - len(code[um.start():um.end()].lstrip())
                yield at, a, _provider_hint(jf, m.start(), None), "crypto.createHmac().update()"
    for m in re.finditer(r"(?:const|let|var)\s+(" + IDENT + r")\s*=\s*[\w$.]*createHmac\s*\(", code):
        for um in re.finditer(r"(?<![\w$.])" + re.escape(m.group(1)) + r"\s*\.\s*update\s*\(", code[m.end():]):
            o = m.end() + um.end() - 1
            a = _arg(code, o, 0)
            if a:
                yield o, a, _provider_hint(jf, m.start(), None), "crypto.createHmac().update()"


def _taint(jf: JsFile, a: int, b: int, scope: tuple[int, int], depth: int = 0) -> tuple[str, str] | None:
    """Is the verification payload clean[a:b] parsed / re-serialized JSON? -> (kind, source)"""
    e = jf.clean[a:b]
    e_code = jf.code[a:b]
    if re.search(r"JSON\s*\.\s*stringify\s*\(", e_code):
        return "stringify", "JSON.stringify(...)"
    if re.search(r"JSON\s*\.\s*parse\s*\(", e_code):
        return "parsed", "JSON.parse(...)"
    jm = re.search(r"(" + IDENT + r"(?:\s*\.\s*" + IDENT + r")*)\s*\.\s*json\s*\(\s*\)", e_code)
    if jm:
        src = re.sub(r"\s+", "", jm.group(1))
        return "parsed", f"await {src}.json()"
    compact = re.sub(r"\s+", "", re.sub(r"\bas\s+[\w.<>\[\]]+", "", e)).rstrip("!")
    if re.fullmatch(r"(?:Buffer\.from\(|String\()?(?:req|request)\.body\)?(?:\.toString\([^)]*\))?!?", compact):
        return "req.body", compact
    if depth >= 3:
        return None
    s0 = scope[0]
    region = jf.code[s0:a]
    for v in dict.fromkeys(re.findall(r"(?<![\w$.])(" + IDENT + r")", e_code)):
        if v in KEYWORDS or v in ("JSON", "Buffer", "String", "req", "request", "TextEncoder", "encoder"):
            continue
        last = None
        for am in re.finditer(r"(?:(?:const|let|var)\s+" + re.escape(v) + r"\s*(?::[^=;]+)?|(?<![\w$.])"
                              + re.escape(v) + r")\s*=(?![=>])\s*", region):
            last = am
        if last is not None:
            rs = s0 + last.end()
            got = _taint(jf, rs, stmt_end(jf.code, rs), scope, depth + 1)
            if got:
                return got
            continue
        if v == "body" and re.search(r"\{[^}]*\bbody\b[^}]*\}\s*=\s*(?:req|request)\b", region):
            return "req.body", "req.body"
    return None


def check_raw_body(jf: JsFile) -> None:
    for off, (a, b), prov, call in _payload_sites(jf):
        p = BY_KEY.get(prov) if prov else None
        if p is not None and not p.raw_body:
            continue
        f = jf.fn_at(off)
        scope = (f.popen, f.bend) if f else (0, len(jf.code))
        got = _taint(jf, a, b, scope)
        if not got:
            continue
        kind, src = got
        label = p.label if p else "The webhook"
        extra = {"provider": prov, "framework": jf.framework, "call": call, "kind": kind}
        if kind == "stringify":
            note = (" JSON.stringify(req.body) is a widely copied Razorpay pattern; it only works while Razorpay's "
                    "serialisation happens to match JSON.stringify's." if prov == "razorpay" else "")
            jf.add("WHK002", "high",
                   f"{label} signature is checked in {call} against {src} (re-serialized JSON), not the raw bytes "
                   f"that were signed: key order, spacing and unicode escapes differ, so real events fail and the "
                   f"check tends to get disabled.{note}", off, **extra)
        elif kind == "parsed":
            jf.add("WHK002", "high",
                   f"{label} signature is checked in {call} against a parsed body ({src}) instead of the raw request "
                   f"text: the signed bytes are already gone.", off, **extra)
        elif kind == "req.body":
            route = jf.route_at(off)
            pages = PAGES_API_RE.search(jf.rel)
            if pages and not re.search(r"bodyParser\s*:\s*false", jf.code):
                extra["framework"] = "next-pages"
                jf.add("WHK002", "high",
                       f"{label} signature is checked in {call} against req.body, which Next.js has already parsed "
                       f"(this file has no `export const config = {{ api: {{ bodyParser: false }} }}`): verification "
                       f"never sees the bytes that were signed.", off, **extra)
            elif route is not None and jf.framework in ("express", "node"):
                uses = list(re.finditer(r"\.\s*use\s*\(\s*(?:(['\"])([^'\"]*)\1\s*,\s*)?(?:express|bodyParser)\s*"
                                        r"\.\s*json\s*\(", jf.clean))
                hit = next((u for u in uses if u.start() < route[0] and
                            (not u.group(2) or route[2].startswith(u.group(2)))), None)
                if hit:
                    extra["framework"] = "express"
                    extra["route"] = route[2]
                    jf.add("WHK002", "high",
                           f"{label} signature is checked in {call} against req.body, but express.json() is "
                           f"registered first (line {jf.line_of(hit.start())}), so req.body is a parsed object here; "
                           f"a route-level express.raw() cannot undo that.", off, **extra)
            elif jf.framework == "fastify" and not re.search(r"addContentTypeParser|rawBody|raw-body", jf.code + jf.clean):
                extra["framework"] = "fastify"
                jf.add("WHK002", "high",
                       f"{label} signature is checked in {call} against request.body, which Fastify has already "
                       f"parsed as JSON (no raw-body content-type parser in this file).", off, **extra)


def check_compare(jf: JsFile) -> None:
    code = jf.code
    digest_vars: set[str] = set()
    hmac_vars: set[str] = set()
    for m in re.finditer(r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*", code):
        rhs = code[m.end():stmt_end(code, m.end())]
        if re.search(r"createHmac\s*\(", rhs) and not re.search(r"\.\s*digest\s*\(", rhs):
            hmac_vars.add(m.group(1))
    for m in re.finditer(r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*", code):
        rhs = code[m.end():stmt_end(code, m.end())]
        if (re.search(r"createHmac\s*\(", rhs) and re.search(r"\.\s*digest\s*\(", rhs)) or \
                any(re.search(r"(?<![\w$.])" + re.escape(h) + r"\s*\.\s*(?:update\s*\([^;]*\)\s*\.\s*)?digest\s*\(", rhs)
                    for h in hmac_vars) or \
                (re.search(r"subtle\s*\.\s*sign\s*\(", rhs)):
            digest_vars.add(m.group(1))
    if not digest_vars and "createHmac" not in code:
        return
    hmac_alt = "|".join(["createHmac", *map(re.escape, hmac_vars)])
    trivial = re.compile(r"^\(?\s*(?:null|undefined|''|\"\"|``|0|true|false|['\"`]\s*['\"`])\s*\)?$")
    for m in re.finditer(r"(?<![=!<>])(===|!==|==|!=)(?!=)", code):
        left = code[code.rfind("\n", 0, m.start()) + 1:m.start()]
        rs = r_end = m.end()
        depth = 0
        while r_end < len(code):
            ch = code[r_end]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (ch in ";,?\n" or code.startswith("&&", r_end) or code.startswith("||", r_end)):
                break
            r_end += 1
        right = code[rs:r_end].strip()
        d = None
        for v in digest_vars:
            if re.search(r"(?<![\w$.])" + re.escape(v) + r"\s*\)?\s*$", left):
                d = v
        if d is None and re.search(r"\.\s*digest\s*\([^()]*\)\s*\)?\s*$", left) and re.search(hmac_alt, left):
            d = "HMAC digest"
        if d is not None:
            other = right
        else:
            for v in digest_vars:
                if re.fullmatch(r"\(?\s*" + re.escape(v) + r"\s*\)?", right):
                    d = v
            if d is None and re.search(hmac_alt, right) and re.search(r"\.\s*digest\s*\([^()]*\)\s*\)?$", right):
                d = "HMAC digest"
            om = re.search(r"([\w$.\[\]'\"`]+(?:\([^()]*\))?)\s*$", left)
            other = om.group(1) if om else ""
        if d is None or not other or trivial.match(other) or re.search(r"\.\s*length\s*\)?$", other) or \
                re.search(r"typeof\s*$", left):
            continue
        name = f"`{d}`" if d != "HMAC digest" else "the HMAC digest"
        jf.add("WHK003", "medium",
               f"HMAC signature {name} is compared with '{m.group(1)}': a non-constant-time comparison leaks how "
               f"much of a forged signature is right (timing attack).",
               m.start(), var=d, op=m.group(1), framework=jf.framework, other=other.strip() if len(other.strip()) <= 60 else None)


def _literals(jf: JsFile):
    """(start, end, value) of real string literals (not inside comments or other strings)."""
    for m in re.finditer(r"""(['"])((?:\\.|(?!\1)[^\\\n])*)\1|`([^`$\\]*)`""", jf.clean):
        s, e = m.start(), m.end()
        if jf.code[s] != jf.clean[s] or jf.code[e - 1] != jf.clean[e - 1]:
            continue
        if jf.code[s + 1:e - 1].strip():
            continue
        yield s, e, m.group(2) if m.group(2) is not None else m.group(3)


SECRET_ARG_CALLS = [
    (re.compile(r"(?<![\w$])constructEvent(?:Async)?\s*\("), 2),
    (re.compile(r"(?<![\w$])validateWebhookSignature\s*\("), 2),
    (re.compile(r"(?<![\w$])validatePaymentVerification\s*\("), 2),
    (re.compile(r"\bcreateHmac\s*\("), 1),
    (re.compile(r"\bnew\s+Webhook\s*\("), 0),
    (re.compile(r"(?<![\w$])validateRequest\s*\("), 0),
    (re.compile(r"\.\s*unmarshal\s*\("), 1),
    (re.compile(r"\bnew\s+Webhooks\s*\(\s*\{[^}]*?secret\s*:\s*"), -1),
]


def check_secrets(jf: JsFile) -> None:
    code, clean = jf.code, jf.clean
    arg_spans: dict[tuple[int, int], str] = {}
    for rx, idx in SECRET_ARG_CALLS:
        for m in rx.finditer(code):
            if idx < 0:
                e = stmt_end(code, m.end())
                e = m.end() + len(code[m.end():e].rstrip())
                arg_spans[(m.end(), e)] = "new Webhooks({ secret })"
                continue
            a = _arg(code, m.end() - 1, idx)
            if a:
                s = a[0] + (len(code[a[0]:a[1]]) - len(code[a[0]:a[1]].lstrip()))
                e = a[0] + len(code[a[0]:a[1]].rstrip())
                arg_spans[(s, e)] = re.sub(r"\s+", "", code[m.start():m.end()]).rstrip("(") + "()"
    hits = []
    for s, e, val in _literals(jf):
        if len(val) < 8 or PLACEHOLDER_RE.search(val) or re.fullmatch(r"[A-Z][A-Z0-9_]+", val) or len(set(val)) < 4:
            continue
        where = None
        whsec = val.startswith("whsec_") and len(val) >= 20
        if (s, e) in arg_spans:
            where = f"passed directly to {arg_spans[(s, e)]}"
        else:
            ls = clean.rfind("\n", 0, s) + 1
            before = code[ls:s]
            before_clean = clean[ls:s]
            am = re.search(r"(?:^|[^\w$.])([A-Za-z_$][\w$.]*)\s*(?::\s*[\w<>\[\]| ]+)?\s*=\s*$", before)
            pm = re.search(r"""(?:^|[\s{,])['"]?([A-Za-z_$][\w$-]*)['"]?\s*:\s*$""", before_clean)
            fm = re.search(r"process\s*\.\s*env\s*(?:\.\s*(\w+)|\[\s*['\"](\w+)['\"]\s*\])\s*(?:\|\||\?\?)\s*$", before_clean)
            if fm and SECRET_NAME_RE.search(fm.group(1) or fm.group(2) or ""):
                where = f"as the fallback for process.env.{fm.group(1) or fm.group(2)}"
            elif am and SECRET_NAME_RE.search(am.group(1).split(".")[-1]):
                where = f"in {am.group(1)}"
            elif pm and SECRET_NAME_RE.search(pm.group(1)):
                where = f"in {pm.group(1)}"
        if where is None and not whsec:
            continue
        hits.append((s, val, whsec, where))
    jf.secrets.extend(v for _, v, _, _ in hits)
    for s, val, whsec, where in hits:
        if whsec:
            msg = (f"Stripe/Svix webhook signing secret (whsec_) hard-coded{(' ' + where) if where else ''}: anyone "
                   f"with the source can sign forged events.")
        else:
            msg = f"Webhook signing secret hard-coded {where}: anyone with the source can sign forged events."
        jf.add("WHK004", "critical" if whsec else "high", msg + f" Value: {mask_secret(val)}.", s,
               var=re.sub(r"^(?:in|as the fallback for|passed directly to)\s+", "", where or "secret"))


EXIT_RE = re.compile(r"\breturn\b|\bthrow\b|\bnext\s*\(\s*[A-Za-z_$]|\bstatus\s*\(\s*4\d\d|\bsendStatus\s*\(|"
                     r"\bResponse\s*\(|\bNextResponse\b|\.\s*code\s*\(\s*4|\breply\s*\.|\bc\s*\.\s*(?:text|json|body)\s*\(|"
                     r"\bprocess\s*\.\s*exit\b|\bres\s*\.\s*(?:end|send|json|status|writeHead)\s*\(|\bctx\s*\.\s*(?:status|throw)\b")
BOOL_VERIFIERS = r"validateWebhookSignature|validatePaymentVerification|timingSafeEqual|validateRequest|isSignatureValid"


def check_swallowed(jf: JsFile) -> None:
    code = jf.code
    for m in re.finditer(r"(?<![\w$])try\s*\{", code):
        bo = m.end() - 1
        bc = match_close(code, bo)
        body = code[bo:bc]
        vm = re.search(r"(?<![\w$])(?:constructEvent(?:Async)?|validateWebhookSignature|verifyWebhook|unmarshal)\s*\(|"
                       r"(?<![\w$])(?:wh|webhook|webhooks|svix|hook)\s*\.\s*verify\s*\(", body, re.I)
        if not vm:
            gm = GENERIC_VERIFY_RE.search(body)
            if not gm or "createHmac" in gm.group(0) or "subtle" in gm.group(0):
                continue
        cm = re.compile(r"\s*catch\s*(?:\(([^)]*)\))?\s*\{").match(code, bc + 1)
        if not cm:
            continue
        co = cm.end() - 1
        cc = match_close(code, co)
        cbody = code[co + 1:cc]
        if EXIT_RE.search(cbody):
            continue
        nm = re.search(r"(?<![\w$.])(" + IDENT + r")\s*=\s*(?:null|undefined|false)\b", cbody)
        if nm and re.search(r"(?:!\s*" + re.escape(nm.group(1)) + r"\b|" + re.escape(nm.group(1)) +
                            r"\s*(?:===?|!==?)\s*(?:null|undefined|false))", code[cc:cc + 3000]):
            continue
        fallback = re.search(r"=\s*(?:await\s+)?(?:req|request|c\s*\.\s*req)\s*\.\s*(?:body|json)|=\s*JSON\s*\.\s*parse", cbody)
        jf.add("WHK005", "high",
               "Signature verification failure is caught and the handler carries on: this catch block neither "
               "returns nor throws" + (", and it falls back to the unverified body" if fallback else "") +
               ", so a forged event is processed anyway.", co, kind="catch", framework=jf.framework)
    for m in re.finditer(r"(?:(?<=[;{}])|^)(\s*)(?:await\s+)?((?:" + IDENT + r"\s*\.\s*)*(" + BOOL_VERIFIERS + r"))\s*\(",
                         code, re.M):
        start = m.start(2)
        prev = code[:m.start()].rstrip()
        if prev and prev[-1] not in ";{}":
            continue
        jf.add("WHK005", "high",
               f"The result of {m.group(3)}() is ignored: it returns false for a bad signature instead of throwing, "
               f"so this line verifies nothing.", start, kind="ignored", call=m.group(3), framework=jf.framework)


def _num(expr: str) -> float | None:
    s = re.sub(r"\s+", "", expr).replace("_", "")
    if s in ("Infinity", "Number.MAX_SAFE_INTEGER", "Number.MAX_VALUE", "Number.POSITIVE_INFINITY"):
        return float("inf")
    if re.fullmatch(r"-?[\d.]+(?:e\d+)?(?:\*[\d.]+)*", s):
        v = 1.0
        for part in s.split("*"):
            v *= float(part)
        return v
    return None


def check_tolerance(jf: JsFile) -> None:
    for m in re.finditer(r"(?<![\w$])constructEvent(?:Async)?\s*\(", jf.code):
        a = _arg(jf.code, m.end() - 1, 3)
        if not a:
            continue
        expr = jf.code[a[0]:a[1]].strip()
        if expr in ("null", "undefined"):
            continue
        v = _num(expr)
        if v is None:
            continue
        if v <= 0:
            desc = f"{expr} (timestamp check disabled)"
        elif v > 600:
            desc = f"{expr} = {int(v) if v != float('inf') else 'infinite'} seconds instead of the default 300"
        else:
            continue
        jf.add("WHK008", "low",
               f"Stripe signature tolerance is {desc}: a captured event (from logs or a proxy) can be replayed "
               f"long after it was sent.", a[0] + len(jf.code[a[0]:a[1]]) - len(jf.code[a[0]:a[1]].lstrip()),
               lang="js")


# ---------------------------------------------------------------- entry point
def is_relevant(text: str, rel: str = "") -> bool:
    """Worth scanning: the code or its path mentions webhooks / a provider (app/api/webhooks/stripe/route.ts
    may never name Stripe in the code itself)."""
    return bool(RELEVANT_RE.search(text) or RELEVANT_RE.search(rel))


def scan_js(rel: str, text: str) -> tuple[list[Finding], list[Handler]]:
    jf = JsFile(rel, text)
    check_secrets(jf)          # first, so every later evidence line is redacted
    b = _Builder(jf)
    b.find_next_app()
    b.find_default_export()
    b.find_nest()
    b.find_deno()
    b.find_express_style()
    explicit = list(b.handlers)
    for h in explicit:
        classify(h, jf.clean)
    b.find_plain_functions()
    handlers = [h for h in b.handlers if h.kind]
    for h in handlers:
        jf.findings.extend(handler_findings(h, jf.secrets))
    check_raw_body(jf)
    check_compare(jf)
    check_swallowed(jf)
    check_tolerance(jf)
    return jf.findings, handlers
