"""
Motor de reconhecimento passivo.

Todas as operações de rede aqui feitas são pedidos HTTP GET/HEAD/OPTIONS de
leitura sobre recursos públicos do alvo informado pelo utilizador (HTML, JS,
CSS, headers, robots.txt, sitemap.xml, source maps, Swagger/OpenAPI) ou,
quando o utilizador o pede explicitamente a partir do frontend, pedidos
pontuais a endpoints descobertos (com os métodos/headers que ele escolher).
Não é efetuada qualquer tentativa automática de exploração, força bruta,
bypass de autenticação ou modificação de estado da aplicação alvo.
"""
import asyncio
import base64
import json
import os
import re
import time
import uuid
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from patterns import (
    HTTP_CALL_PATTERNS, GENERIC_PATH_PATTERN, ABSOLUTE_URL_PATTERN,
    API_DOC_PATHS, STATIC_TARGETS, ENV_VAR_PATTERN, PROCESS_ENV_PATTERN,
    IMPORT_META_ENV_PATTERN, SECRET_PATTERNS, JWT_PATTERN,
    STORAGE_USAGE_PATTERN, PII_PATTERNS, SECURITY_HEADERS,
    DEFAULT_BROWSER_HEADERS, RESERVED_HEADERS, STACK_FINGERPRINT_FILES,
    STORAGE_SENSITIVE_KEYS, BASE64_LIKE_PATTERN, HEX_LIKE_PATTERN,
    PII_PLACEHOLDER_DOMAINS, PII_PLACEHOLDER_LOCAL_PARTS,
    PII_PLACEHOLDER_UUIDS, PII_PLACEHOLDER_PHONE_PREFIXES,
    SECRET_RELEVANCE, PII_RELEVANCE, PROBE_METHODS,
    METHOD_ENABLED_STATUS_HINTS,
    GENERIC_CLIENT_CALL_PATTERN, ROUTE_ARROW_LITERAL_PATTERN,
    ROUTE_ARROW_TEMPLATE_PATTERN, ALIASED_ENV_ACCESS_PATTERN,
    ALIASED_ENV_FALLBACK_PATTERN, BASIC_AUTH_BUILD_PATTERN,
    ROBOTS_DIRECTIVE_PATTERN, SITEMAP_LOC_PATTERN,
    SWAGGER_JSON_KEYS, SWAGGER_HTML_MARKERS,
)

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
MAX_JS_FILES = 40          # limite de segurança para não sobrecarregar o alvo
MAX_FILE_BYTES = 2_000_000  # 2MB por ficheiro


def _safe_dir_name(url: str) -> str:
    host = urlparse(url).netloc.replace(":", "_")
    return f"{host}_{uuid.uuid4().hex[:8]}"


def build_headers(custom_headers: dict | None = None) -> dict:
    """Combina o User-Agent/Accept de navegador por omissão com headers
    customizados fornecidos pelo utilizador (Authorization, Cookie, etc.).
    Headers customizados têm prioridade e podem sobrepor até o User-Agent."""
    headers = dict(DEFAULT_BROWSER_HEADERS)
    if custom_headers:
        for k, v in custom_headers.items():
            if not k or v is None:
                continue
            if k.lower() in RESERVED_HEADERS:
                continue
            headers[k] = str(v)
    return headers


class ProgressReporter:
    """Encapsula o envio de eventos de progresso para a fila SSE do job."""

    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    async def emit(self, stage: str, message: str, percent: int, data: dict | None = None):
        await self.queue.put({
            "stage": stage,
            "message": message,
            "percent": percent,
            "data": data or {},
        })


async def _get(client: httpx.AsyncClient, url: str, **kwargs):
    try:
        resp = await client.get(url, timeout=15, follow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None


async def _get_no_redirect(client: httpx.AsyncClient, url: str, **kwargs):
    try:
        resp = await client.get(url, timeout=15, follow_redirects=False, **kwargs)
        return resp
    except Exception:
        return None


def _decode_jwt(token: str) -> dict | None:
    try:
        header_b64, payload_b64, _sig = token.split(".")

        def pad(s):
            return s + "=" * (-len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
        return {"header": header, "payload": payload}
    except Exception:
        return None


def _classify_module(path: str) -> str:
    known = ["admin", "dashboard", "auth", "users", "roles", "permissions",
             "services", "settings", "documents", "profile", "workflow",
             "billing", "orders", "products", "reports"]
    lowered = path.lower()
    for k in known:
        if k in lowered:
            return k
    return "outro"


def _is_placeholder_email(email: str) -> bool:
    email_lower = email.lower()
    local, _, domain = email_lower.partition("@")
    if domain in PII_PLACEHOLDER_DOMAINS:
        return True
    if local in PII_PLACEHOLDER_LOCAL_PARTS:
        return True
    if domain.endswith((".local", ".test", ".invalid", ".example")):
        return True
    if len(local) >= 3 and len(set(local)) == 1:  # ex.: "aaaa", "xxxx"
        return True
    return False


def _is_placeholder_phone(value: str) -> bool:
    digits_only = re.sub(r"\D", "", value)
    if len(set(digits_only)) <= 2:  # ex.: 000000000, 111111111
        return True
    return value.startswith(PII_PLACEHOLDER_PHONE_PREFIXES)


def _is_placeholder_uuid(value: str) -> bool:
    return value.lower() in PII_PLACEHOLDER_UUIDS


def _is_placeholder_pii(pii_type: str, value: str) -> bool:
    if pii_type == "email":
        return _is_placeholder_email(value)
    if pii_type == "phone_intl":
        return _is_placeholder_phone(value)
    if pii_type == "uuid":
        return _is_placeholder_uuid(value)
    if pii_type in ("cpf", "nif_pt"):
        digits_only = re.sub(r"\D", "", value)
        return len(set(digits_only)) <= 1  # 000.000.000-00, 111111111, etc.
    return False


def _storage_key_relevance(key: str) -> str:
    key_lower = key.lower()
    for sensitive in STORAGE_SENSITIVE_KEYS:
        if sensitive in key_lower:
            return "high"
    return "low"


_API_LIKE_HINT = re.compile(r"^(https?://|/|v[0-9]+/|api/|graphql|rest/)", re.I)
# métodos de objetos JS comuns (Map/Set/URLSearchParams/Storage/...) que também
# se chamam ".get("chave")" mas nada têm a ver com chamadas de rede — usados
# para descartar ruído do GENERIC_CLIENT_CALL_PATTERN.
_NON_HTTP_GET_RECEIVERS = {
    "map", "params", "searchparams", "urlsearchparams", "formdata",
    "localstorage", "sessionstorage", "cache", "headers", "cookies",
    "queryclient",
}


def _looks_like_api_path(path: str) -> bool:
    """Filtra ruído do GENERIC_CLIENT_CALL_PATTERN: só aceita strings que
    pareçam mesmo um caminho/URL de API (absoluta, começando por '/', por
    'v<n>/' ou contendo 'api'/'graphql'/'rest'), evitando falsos positivos de
    chamadas como Map.get("chave") ou i18n.get("label")."""
    if not path or len(path) > 300:
        return False
    return bool(_API_LIKE_HINT.match(path.strip()))


def _receiver_is_non_http(receiver: str) -> bool:
    last = receiver.split(".")[-1].lower()
    return last in _NON_HTTP_GET_RECEIVERS


def _route_value_is_plausible(path: str) -> bool:
    """Descarta chaves de rota óbvias que não são realmente caminhos de UI
    (ex.: valores vazios, ou apenas '/')."""
    if not path or len(path) > 250:
        return False
    if re.search(r"[<>]", path):
        return False
    return True


def _classify_secret_relevance(secret_type: str, matched_value: str) -> str:
    base = SECRET_RELEVANCE.get(secret_type, "medium")
    # eleva heurísticas genéricas (env fallback / const url / axios baseURL)
    # quando o nome sugere algo sensível (token/secret/key/password)
    if secret_type in ("env_fallback_literal", "hardcoded_const_url", "axios_base_url"):
        lowered = matched_value.lower()
        if any(w in lowered for w in ("secret", "token", "key", "password", "credential")):
            return "high"
    return base


class ReconAnalyzer:
    def __init__(self, target_url: str, progress: ProgressReporter,
                 custom_headers: dict | None = None, options: dict | None = None):
        self.target_url = target_url.rstrip("/")
        self.progress = progress
        self.parsed = urlparse(self.target_url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.job_dir = os.path.join(STORAGE_DIR, _safe_dir_name(self.target_url))
        os.makedirs(self.job_dir, exist_ok=True)

        self.custom_headers = custom_headers or {}
        self.headers = build_headers(self.custom_headers)

        opts = options or {}
        self.opt_probe_stack_files = opts.get("probe_stack_files", True)
        self.opt_probe_external_domains = opts.get("probe_external_domains", True)
        self.opt_infer_methods = opts.get("infer_http_methods", False)

        self.report = {
            "target": self.target_url,
            "final_url": self.target_url,
            "technologies": [],
            "technologies_detail": [],
            "http": {},
            "cookies": [],
            "files_downloaded": [],
            "js_files": [],
            "endpoints": [],
            "routes": [],
            "robots_findings": [],
            "sitemap_urls": [],
            "api_docs": [],
            "env_vars": [],
            "secrets": [],
            "jwts": [],
            "storage_usage": [],
            "pii": [],
            "external_domains": [],
            "external_domain_recon": [],
            "modules": [],
            "headers_sent": {k: v for k, v in self.headers.items()},
            "stats": {},
        }

    # ------------------------------------------------------------------
    async def run(self) -> dict:
        async with httpx.AsyncClient(headers=self.headers) as client:
            await self.progress.emit("fingerprint", "Detectando tecnologias e cabeçalhos HTTP...", 5)
            html_text = await self._fingerprint(client)

            if self.opt_probe_stack_files and self.report["technologies"]:
                await self.progress.emit("stackfiles", "Confirmando stack via arquivos característicos...", 12)
                await self._probe_stack_files(client)

            await self.progress.emit("static", "Baixando recursos estáticos (robots, sitemap, manifest)...", 18)
            await self._download_static(client)

            await self.progress.emit("discovery", "Descobrindo arquivos JavaScript...", 25)
            js_urls = await self._discover_js(client, html_text)

            await self.progress.emit("download", "Baixando arquivos JavaScript...", 35, {"total": len(js_urls)})
            js_contents = await self._download_js(client, js_urls)

            await self.progress.emit("parsing", "Analisando arquivos JavaScript...", 50)
            self._parse_js(js_contents)

            await self.progress.emit("apidocs", "Procurando documentação de API (Swagger/OpenAPI)...", 62)
            await self._discover_api_docs(client, html_text)

            await self.progress.emit("pii", "Extraindo PII, secrets e tokens...", 75)
            self._extract_pii_and_secrets(html_text, js_contents)

            if self.opt_probe_external_domains and self.report["external_domains"]:
                await self.progress.emit("extdomains", "Reconhecendo domínios externos...", 85)
                await self._recon_external_domains(client)

            await self.progress.emit("stats", "Gerando estatísticas finais...", 95)
            self._compute_stats()

            await self.progress.emit("done", "Análise concluída.", 100)
            self._save_report_file()
            return self.report

    # ------------------------------------------------------------------
    async def _fingerprint(self, client: httpx.AsyncClient) -> str:
        # pedido sem seguir redirect automaticamente para poder documentar a
        # cadeia manualmente; depois fazemos o pedido final já resolvido.
        resp = await _get(client, self.target_url)
        html_text = ""
        if resp is not None:
            html_text = resp.text

            # cadeia de redirecionamentos (301/302/307/308, ...) até o destino final
            redirect_chain = []
            for hop in resp.history:
                redirect_chain.append({
                    "status_code": hop.status_code,
                    "from_url": str(hop.url),
                    "location": hop.headers.get("location"),
                })
            final_url = str(resp.url)
            if redirect_chain:
                self.report["final_url"] = final_url
                # se o destino final mudou de host, ajusta a base para que a
                # descoberta de JS/endpoints continue a partir do destino real
                final_parsed = urlparse(final_url)
                self.base = f"{final_parsed.scheme}://{final_parsed.netloc}"
                self.parsed = final_parsed

            headers = dict(resp.headers)
            self.report["http"] = {
                "status_code": resp.status_code,
                "headers": headers,
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "content_type": headers.get("content-type"),
                "cache_control": headers.get("cache-control"),
                "etag": headers.get("etag"),
                "redirect_chain": redirect_chain,
                "final_url": final_url,
                "security_headers": {
                    h: headers.get(h) for h in SECURITY_HEADERS if h in {k.lower() for k in headers}
                },
            }
            self.report["cookies"] = self._parse_cookies(resp)
            self._save_file("index.html", html_text)
            self.report["files_downloaded"].append("index.html")

            techs: dict[str, list[str]] = {}  # nome -> evidências

            def add_tech(name, evidence):
                techs.setdefault(name, []).append(evidence)

            server = (headers.get("server") or "").lower()
            powered = (headers.get("x-powered-by") or "").lower()
            if "cloudflare" in server:
                add_tech("Cloudflare", f"header Server: {headers.get('server')}")
            if "nginx" in server:
                add_tech("Nginx", f"header Server: {headers.get('server')}")
            if "apache" in server:
                add_tech("Apache", f"header Server: {headers.get('server')}")
            if "iis" in server:
                add_tech("IIS", f"header Server: {headers.get('server')}")
            if "express" in powered:
                add_tech("Express", f"header X-Powered-By: {headers.get('x-powered-by')}")
            if "asp.net" in powered or "asp.net" in server:
                add_tech("ASP.NET", "header Server/X-Powered-By")
            if "php" in powered:
                add_tech("PHP", f"header X-Powered-By: {headers.get('x-powered-by')}")
            if headers.get("x-drupal-cache") or "drupal" in html_text.lower():
                add_tech("Drupal", "header/marcador X-Drupal-Cache ou HTML")

            soup = BeautifulSoup(html_text, "html.parser")
            if soup.find(id="__next") or "/_next/static" in html_text:
                add_tech("Next.js", "id=__next ou /_next/static presente no HTML")
            if soup.find(id="root") and "/static/js/" in html_text:
                add_tech("React", "id=root + /static/js/ (padrão create-react-app)")
            if "ng-version" in html_text or soup.find(attrs={"ng-version": True}):
                add_tech("Angular", "atributo ng-version presente no HTML")
            if "vue" in html_text.lower() and "/assets/" in html_text:
                add_tech("Vue", "marcador 'vue' + /assets/ no HTML")
            if "__nuxt" in html_text.lower() or "/_nuxt/" in html_text:
                add_tech("Nuxt.js", "marcador __nuxt ou /_nuxt/ no HTML")
            if "supabase" in html_text.lower():
                add_tech("Supabase", "marcador 'supabase' no HTML")
            if "firebase" in html_text.lower():
                add_tech("Firebase", "marcador 'firebase' no HTML")
            if "csrf-token" in html_text.lower() and "laravel" in html_text.lower():
                add_tech("Laravel", "meta csrf-token + marcador 'laravel'")
            elif soup.find("meta", attrs={"name": "csrf-token"}):
                add_tech("Laravel", "meta name=csrf-token (comum em Laravel Blade)")
            if "wp-content" in html_text.lower() or "wp-json" in html_text.lower():
                add_tech("WordPress", "marcador wp-content/wp-json no HTML")
            if "csrfmiddlewaretoken" in html_text.lower() or "django" in powered:
                add_tech("Django", "marcador csrfmiddlewaretoken no HTML")
            for meta in soup.find_all("meta"):
                if meta.get("name") == "generator" and meta.get("content"):
                    add_tech(meta["content"], "meta name=generator")

            self.report["technologies"] = sorted(techs.keys())
            self.report["technologies_detail"] = [
                {"name": name, "evidence": ev, "confirmed_files": []}
                for name, ev in sorted(techs.items())
            ]
        return html_text

    def _parse_cookies(self, resp: httpx.Response) -> list[dict]:
        cookies = []
        for raw in resp.headers.get_list("set-cookie"):
            parts = [p.strip() for p in raw.split(";")]
            name_value = parts[0].split("=", 1)
            entry = {
                "name": name_value[0],
                "http_only": any(p.lower() == "httponly" for p in parts[1:]),
                "secure": any(p.lower() == "secure" for p in parts[1:]),
                "same_site": next((p.split("=")[1] for p in parts[1:] if p.lower().startswith("samesite")), None),
                "domain": next((p.split("=")[1] for p in parts[1:] if p.lower().startswith("domain")), None),
                "path": next((p.split("=")[1] for p in parts[1:] if p.lower().startswith("path")), None),
                "expires": next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("expires")), None),
                "source_type": "header",
                "source_file": "Set-Cookie (resposta HTTP inicial)",
            }
            cookies.append(entry)
        return cookies

    # ------------------------------------------------------------------
    async def _probe_stack_files(self, client: httpx.AsyncClient):
        """Para cada tecnologia detectada por heurística, sonda os arquivos
        característicos daquela stack para confirmar (ou não) a detecção."""
        detail_by_name = {d["name"]: d for d in self.report["technologies_detail"]}
        for tech_name in list(self.report["technologies"]):
            candidate_paths = STACK_FINGERPRINT_FILES.get(tech_name)
            if not candidate_paths:
                continue
            for path in candidate_paths:
                url = urljoin(self.base + "/", path.lstrip("/"))
                resp = await _get(client, url)
                if resp is not None and resp.status_code < 400:
                    entry = detail_by_name.get(tech_name)
                    if entry is not None:
                        entry["confirmed_files"].append({
                            "path": path, "url": url, "status_code": resp.status_code,
                        })

    # ------------------------------------------------------------------
    async def _download_static(self, client: httpx.AsyncClient):
        for path in STATIC_TARGETS:
            url = urljoin(self.base + "/", path.lstrip("/"))
            resp = await _get(client, url)
            if resp is not None and resp.status_code == 200:
                fname = path.lstrip("/").replace("/", "_")
                text = resp.text if self._is_text(resp) else ""
                self._save_file(fname, text)
                self.report["files_downloaded"].append(fname)

                if path == "/robots.txt" and text:
                    self._parse_robots(text)
                elif path == "/sitemap.xml" and text:
                    self._parse_sitemap(text)

    def _parse_robots(self, text: str):
        """Extrai diretivas Disallow/Allow/Sitemap do robots.txt. São
        pistas valiosas de rotas/áreas que o operador tentou esconder de
        motores de busca (painéis admin, rotas internas, etc.) — não é
        acessado automaticamente, apenas listado como candidato para o
        utilizador decidir se quer inspecionar."""
        for m in ROBOTS_DIRECTIVE_PATTERN.finditer(text):
            directive, value = m.group(1).capitalize(), m.group(2).strip()
            if directive == "Sitemap":
                self.report["sitemap_urls"].append(value)
                continue
            if not value or value == "/":
                continue
            full_url = urljoin(self.base + "/", value.lstrip("/"))
            self.report["robots_findings"].append({
                "directive": directive,
                "path": value,
                "full_url": full_url,
            })
        # dedup preservando ordem
        seen = set()
        deduped = []
        for entry in self.report["robots_findings"]:
            key = (entry["directive"], entry["path"])
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        self.report["robots_findings"] = deduped

    def _parse_sitemap(self, text: str):
        """Extrai URLs <loc> de sitemap.xml (e sitemap index) como rotas
        candidatas adicionais."""
        for m in SITEMAP_LOC_PATTERN.finditer(text):
            url = m.group(1).strip()
            if url and url not in self.report["sitemap_urls"]:
                self.report["sitemap_urls"].append(url)

    @staticmethod
    def _is_text(resp: httpx.Response) -> bool:
        ct = resp.headers.get("content-type", "")
        return any(t in ct for t in ["text", "json", "xml", "javascript"])

    # ------------------------------------------------------------------
    async def _discover_js(self, client: httpx.AsyncClient, html_text: str) -> list[str]:
        soup = BeautifulSoup(html_text, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            js_urls.add(urljoin(self.target_url + "/", script["src"]))
        for link in soup.find_all("link", href=True):
            if link["href"].endswith(".map"):
                js_urls.add(urljoin(self.target_url + "/", link["href"]))

        return list(js_urls)[:MAX_JS_FILES]

    async def _download_js(self, client: httpx.AsyncClient, js_urls: list[str]) -> dict[str, str]:
        contents = {}
        sem = asyncio.Semaphore(8)

        async def fetch_one(u):
            async with sem:
                resp = await _get(client, u)
                if resp is not None and resp.status_code == 200 and len(resp.content) <= MAX_FILE_BYTES:
                    contents[u] = resp.text
                    fname = re.sub(r"[^a-zA-Z0-9_.-]", "_", urlparse(u).path.lstrip("/")) or "script.js"
                    self._save_file(fname, resp.text)
                    self.report["js_files"].append({"url": u, "size": len(resp.content)})
                    self.report["files_downloaded"].append(fname)

                    # tentar baixar source map associado, se referenciado
                    map_match = re.search(r"//#\s*sourceMappingURL=(\S+)", resp.text)
                    if map_match:
                        map_url = urljoin(u, map_match.group(1))
                        map_resp = await _get(client, map_url)
                        if map_resp is not None and map_resp.status_code == 200:
                            map_fname = fname + ".map"
                            self._save_file(map_fname, map_resp.text)
                            self.report["files_downloaded"].append(map_fname)

        await asyncio.gather(*(fetch_one(u) for u in js_urls))
        return contents

    # ------------------------------------------------------------------
    def _parse_js(self, js_contents: dict[str, str]):
        endpoints = {}
        env_vars = {}  # nome -> set(sources)
        domains = set()

        routes: dict = {}  # path_template -> {"keys": set(), "sources": set(), "has_param": bool}

        for url, content in js_contents.items():
            for m in HTTP_CALL_PATTERNS["fetch"].finditer(content):
                self._register_endpoint(endpoints, "GET", m.group(1), url)
            for m in HTTP_CALL_PATTERNS["axios"].finditer(content):
                self._register_endpoint(endpoints, m.group(1).upper(), m.group(2), url)
            for m in HTTP_CALL_PATTERNS["xhr_open"].finditer(content):
                self._register_endpoint(endpoints, m.group(1).upper(), m.group(2), url)
            for m in HTTP_CALL_PATTERNS["websocket"].finditer(content):
                self._register_endpoint(endpoints, "WS", m.group(1), url)
            for m in GENERIC_PATH_PATTERN.finditer(content):
                self._register_endpoint(endpoints, "GET", m.group(1), url)

            # chamadas HTTP em clientes minificados/renomeados: s.default.get(...),
            # s.api.post(\`v1/x/${e}\`), etc. — filtra ruído (Map.get, i18n.get...)
            # exigindo que o receiver não seja um objeto não-HTTP conhecido e que
            # o path pareça mesmo uma rota/URL de API.
            for m in GENERIC_CLIENT_CALL_PATTERN.finditer(content):
                receiver, method, path = m.group(1), m.group(2), m.group(3)
                if _receiver_is_non_http(receiver):
                    continue
                if not _looks_like_api_path(path):
                    continue
                self._register_endpoint(endpoints, method.upper(), path, url)

            # rotas de frontend (\"route builders\"): chave:()=>"/caminho" ou
            # chave:e=>\`/caminho/${e}/editar\`
            for m in ROUTE_ARROW_LITERAL_PATTERN.finditer(content):
                key, path = m.group(1), m.group(2)
                if not _route_value_is_plausible(path):
                    continue
                entry = routes.setdefault(path, {"keys": set(), "sources": set(), "has_param": False})
                entry["keys"].add(key)
                entry["sources"].add(url)
            for m in ROUTE_ARROW_TEMPLATE_PATTERN.finditer(content):
                key, path = m.group(1), m.group(2)
                if not _route_value_is_plausible(path):
                    continue
                entry = routes.setdefault(path, {"keys": set(), "sources": set(), "has_param": True})
                entry["keys"].add(key)
                entry["has_param"] = True
                entry["sources"].add(url)

            # variáveis de ambiente (com origem) — inclui aliases de "process"
            # comuns em bundles minificados (ex.: i.default.env.GOV_API_USERNAME)
            for pattern in (ENV_VAR_PATTERN, PROCESS_ENV_PATTERN, IMPORT_META_ENV_PATTERN,
                             ALIASED_ENV_ACCESS_PATTERN):
                for m in pattern.finditer(content):
                    name = m.group(1) if m.lastindex else m.group(0)
                    env_vars.setdefault(name, set()).add(url)

            # JWTs
            for m in JWT_PATTERN.finditer(content):
                token = m.group(0)
                decoded = _decode_jwt(token)
                if decoded:
                    self.report["jwts"].append({
                        "token_preview": token[:24] + "...",
                        "header": decoded["header"],
                        "payload": decoded["payload"],
                        "source_type": "javascript",
                        "source_file": url,
                    })

            # uso de storage — com classificação de relevância por nome de chave
            for m in STORAGE_USAGE_PATTERN.finditer(content):
                key = m.group(3)
                self.report["storage_usage"].append({
                    "api": m.group(1),
                    "method": m.group(2),
                    "key": key,
                    "relevance": _storage_key_relevance(key),
                    "source_type": "javascript",
                    "source_file": url,
                })

            # domínios externos referenciados
            for m in ABSOLUTE_URL_PATTERN.finditer(content):
                domain = urlparse(m.group(0)).netloc
                if domain and domain != self.parsed.netloc:
                    domains.add(domain)

        for path, info in endpoints.items():
            module = _classify_module(path)
            candidate_urls = self._candidate_urls_for_path(path)
            self.report["endpoints"].append({
                "path": path,
                "methods": sorted(info["methods"]),
                "module": module,
                "sources": sorted(info["sources"]),
                # quando o path é relativo (ex.: "v1/applicants", sem "/" inicial,
                # visto em chamadas tipo s.api.get("v1/applicants")), o prefixo
                # real (montado em runtime por um baseURL configurado no bundler/
                # env, que a análise estática não resolve) é ambíguo — em vez de
                # adivinhar, geramos as combinações mais comuns (/api/v1/..., /v1/...)
                # para o utilizador escolher/testar no painel de execução.
                "candidate_urls": candidate_urls,
            })

        for path, info in routes.items():
            self.report["routes"].append({
                "path": path,
                "full_url": urljoin(self.base + "/", path.lstrip("/")),
                "keys": sorted(info["keys"]),
                "has_param": info["has_param"],
                "sources": sorted(info["sources"]),
            })
        self.report["routes"].sort(key=lambda r: r["path"])

        self.report["env_vars"] = [
            {"name": name, "source_type": "javascript", "sources": sorted(srcs)}
            for name, srcs in sorted(env_vars.items())
        ]
        self.report["external_domains"] = sorted(domains)
        self.report["modules"] = sorted({e["module"] for e in self.report["endpoints"]})

    @staticmethod
    def _register_endpoint(endpoints: dict, method: str, path: str, source: str):
        if not path or len(path) > 300:
            return
        entry = endpoints.setdefault(path, {"methods": set(), "sources": set()})
        entry["methods"].add(method)
        entry["sources"].add(source)

    def _candidate_urls_for_path(self, path: str) -> list[str]:
        """Gera as URLs plausíveis para um path descoberto num bundle JS.
        Paths absolutos (http...) ou já iniciados por "/" têm uma única
        interpretação óbvia. Paths relativos (ex.: "v1/applicants", comuns em
        clientes HTTP configurados com baseURL dinâmico, como visto em
        `s.api.get("v1/applicants")`) são ambíguos estaticamente — o baseURL
        real só existe em runtime — então oferecemos as combinações mais
        comuns para o utilizador testar: com e sem o prefixo "/api"."""
        if path.startswith("http://") or path.startswith("https://"):
            return [path]
        if path.startswith("/"):
            return [urljoin(self.base + "/", path.lstrip("/"))]
        stripped = path.lstrip("/")
        candidates = [
            urljoin(self.base + "/api/", stripped),
            urljoin(self.base + "/", stripped),
        ]
        # dedup preservando ordem
        seen = set()
        out = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    # ------------------------------------------------------------------
    async def _discover_api_docs(self, client: httpx.AsyncClient, home_html: str = ""):
        """Sonda os caminhos comuns de documentação de API e valida o
        conteúdo antes de reportar um achado. Isto evita o falso positivo
        mais comum nesta etapa: SPAs (Next.js/React Router/Vue Router) que
        respondem 200 com o mesmo HTML da home para *qualquer* caminho não
        mapeado ("catch-all"), o que antes fazia /swagger, /docs, /api-docs
        etc. parecerem "encontrados" mesmo quando não existem de verdade."""
        home_len = len(home_html or "")
        home_sample = (home_html or "")[:2000]

        for path in API_DOC_PATHS:
            url = urljoin(self.base + "/", path.lstrip("/"))
            resp = await _get(client, url)
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text if self._is_text(resp) else ""
            ct = resp.headers.get("content-type", "")
            is_json_like = "json" in ct or path.endswith(".json")
            is_yaml_like = path.endswith(".yaml") or path.endswith(".yml")

            valid = False
            spec_info = {}

            if is_json_like:
                try:
                    spec = resp.json()
                    if isinstance(spec, dict) and any(k in spec for k in SWAGGER_JSON_KEYS) and "paths" in spec:
                        valid = True
                        spec_info["endpoints_count"] = len(spec.get("paths", {}))
                        spec_info["title"] = spec.get("info", {}).get("title")
                except Exception:
                    pass
            elif is_yaml_like:
                # heurística leve sem depender de parser YAML: procura as
                # chaves top-level típicas de uma spec OpenAPI/Swagger.
                head = body[:1000].lower()
                if re.search(r"^(swagger|openapi)\s*:", head, re.M) and re.search(r"^paths\s*:", body[:5000], re.M | re.I):
                    valid = True
            else:
                lowered = body[:5000].lower()
                if any(marker in lowered for marker in SWAGGER_HTML_MARKERS):
                    valid = True

            if not valid:
                # descarta silenciosamente o caso clássico de SPA catch-all:
                # corpo idêntico (ou quase) ao da home em tamanho e prefixo.
                is_probable_spa_catchall = (
                    home_len > 0 and abs(len(body) - home_len) < 50
                    and body[:2000] == home_sample
                )
                if is_probable_spa_catchall:
                    continue
                # não bate com nenhuma assinatura conhecida de Swagger/OpenAPI
                # e não é claramente um catch-all — regista como "não confirmado"
                # em vez de omitir, mas sem tratar como achado válido.
                self.report["api_docs"].append({
                    "path": path, "url": url, "status_code": resp.status_code,
                    "confirmed": False,
                    "note": "200 OK mas o conteúdo não corresponde a uma assinatura "
                            "válida de Swagger/OpenAPI — possível falso positivo "
                            "(ex.: página catch-all da SPA). Confirme manualmente.",
                })
                continue

            entry = {"path": path, "url": url, "status_code": resp.status_code, "confirmed": True, **spec_info}
            self.report["api_docs"].append(entry)
            fname = re.sub(r"[^a-zA-Z0-9_.-]", "_", path.lstrip("/")) or "apidoc"
            self._save_file(fname, body)

    # ------------------------------------------------------------------
    def _extract_pii_and_secrets(self, html_text: str, js_contents: dict[str, str]):
        all_texts = {"index.html": html_text, **js_contents}
        seen_secrets = set()
        seen_pii = set()

        for source, text in all_texts.items():
            if not text:
                continue
            source_type = "html" if source == "index.html" else "javascript"

            for name, pattern in SECRET_PATTERNS.items():
                for m in pattern.finditer(text):
                    value = m.group(0)
                    key = (name, value)
                    if key in seen_secrets:
                        continue
                    seen_secrets.add(key)
                    self.report["secrets"].append({
                        "type": name,
                        "match_preview": value[:80] + ("..." if len(value) > 80 else ""),
                        "relevance": _classify_secret_relevance(name, value),
                        "source_type": source_type,
                        "source_file": source,
                    })

            for name, pattern in PII_PATTERNS.items():
                for m in pattern.finditer(text):
                    value = m.group(0)
                    key = (name, value)
                    if key in seen_pii:
                        continue
                    if _is_placeholder_pii(name, value):
                        continue  # falso positivo conhecido (placeholder/dado fictício)
                    seen_pii.add(key)
                    self.report["pii"].append({
                        "type": name,
                        "value": value,
                        "relevance": PII_RELEVANCE.get(name, "medium"),
                        "source_type": source_type,
                        "source_file": source,
                    })

    # ------------------------------------------------------------------
    async def _recon_external_domains(self, client: httpx.AsyncClient):
        """Para cada domínio externo encontrado, faz um pedido de
        reconhecimento (seguindo redirects) e sonda caminhos comuns de
        documentação/painéis/buckets."""
        probe_paths = [
            "/", "/swagger.json", "/openapi.json", "/swagger-ui/", "/docs",
            "/admin", "/.well-known/security.txt",
        ]
        sem = asyncio.Semaphore(5)

        async def recon_one(domain: str):
            async with sem:
                base_url = f"https://{domain}"
                entry = {"domain": domain, "base_url": base_url, "reachable": False,
                         "redirect_chain": [], "final_url": None, "findings": []}
                resp = await _get(client, base_url)
                if resp is None:
                    entry["error"] = "sem resposta (timeout ou conexão recusada)"
                    self.report["external_domain_recon"].append(entry)
                    return
                entry["reachable"] = True
                entry["status_code"] = resp.status_code
                entry["final_url"] = str(resp.url)
                entry["redirect_chain"] = [
                    {"status_code": h.status_code, "from_url": str(h.url),
                     "location": h.headers.get("location")}
                    for h in resp.history
                ]
                for extra in probe_paths[1:]:
                    purl = urljoin(base_url + "/", extra.lstrip("/"))
                    presp = await _get(client, purl)
                    if presp is not None and presp.status_code < 400:
                        kind = "documentação/API" if any(
                            w in extra for w in ("swagger", "openapi", "docs")
                        ) else "painel administrativo" if "admin" in extra else "outro"
                        entry["findings"].append({
                            "path": extra, "url": purl,
                            "status_code": presp.status_code, "kind": kind,
                        })
                self.report["external_domain_recon"].append(entry)

        await asyncio.gather(*(recon_one(d) for d in self.report["external_domains"][:15]))

    # ------------------------------------------------------------------
    def _compute_stats(self):
        r = self.report
        r["stats"] = {
            "js_files": len(r["js_files"]),
            "endpoints": len(r["endpoints"]),
            "routes": len(r["routes"]),
            "external_domains": len(r["external_domains"]),
            "api_docs": len(r["api_docs"]),
            "api_docs_confirmed": sum(1 for d in r["api_docs"] if d.get("confirmed")),
            "robots_findings": len(r["robots_findings"]),
            "secrets": len(r["secrets"]),
            "cookies": len(r["cookies"]),
            "jwts": len(r["jwts"]),
            "env_vars": len(r["env_vars"]),
            "pii": len(r["pii"]),
            "files_downloaded": len(r["files_downloaded"]),
        }

    # ------------------------------------------------------------------
    def _save_file(self, name: str, content: str):
        try:
            path = os.path.join(self.job_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content or "")
        except Exception:
            pass

    def _save_report_file(self):
        path = os.path.join(self.job_dir, "relatorio.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, ensure_ascii=False, indent=2)


# ===========================================================================
# Execução de requisições avulsas a partir do frontend ("Executar" num
# endpoint descoberto) + inferência de métodos HTTP suportados.
# ===========================================================================
def _analyze_response_text(text: str) -> dict:
    """Corre a extração de PII/secrets/JWT/URLs sobre o texto de uma resposta
    de endpoint (JSON serializado ou corpo texto/HTML puro), para dar
    visibilidade imediata ao utilizador quando ele testa uma rota/API
    descoberta a partir do painel de execução — não só em respostas JSON,
    já que respostas de erro, HTML ou texto simples também podem vazar
    emails e outras PII."""
    findings = {"pii": [], "secrets": [], "jwts": [], "urls": []}

    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group(0)
            findings["secrets"].append({
                "type": name,
                "match_preview": value[:80] + ("..." if len(value) > 80 else ""),
                "relevance": _classify_secret_relevance(name, value),
            })

    for name, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group(0)
            if _is_placeholder_pii(name, value):
                continue
            findings["pii"].append({
                "type": name, "value": value,
                "relevance": PII_RELEVANCE.get(name, "medium"),
            })

    for m in JWT_PATTERN.finditer(text):
        token = m.group(0)
        decoded = _decode_jwt(token)
        if decoded:
            findings["jwts"].append({
                "token_preview": token[:24] + "...",
                "header": decoded["header"],
                "payload": decoded["payload"],
            })

    for m in ABSOLUTE_URL_PATTERN.finditer(text):
        findings["urls"].append(m.group(0))
    findings["urls"] = sorted(set(findings["urls"]))

    return findings


def _is_probably_text_body(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in ("text", "json", "xml", "javascript", "html")) or ct == ""


async def execute_probe(url: str, method: str = "GET", headers: dict | None = None,
                         body: str | None = None) -> dict:
    """Executa uma única requisição escolhida pelo utilizador no frontend
    contra um endpoint descoberto, e devolve método, status, tempo de
    resposta, corpo e — se JSON — a análise automática de PII/secrets/JWT."""
    req_headers = build_headers(headers)
    method = method.upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise ValueError("Método HTTP não suportado.")

    started = time.perf_counter()
    result = {
        "url": url, "method": method, "status_code": None,
        "elapsed_ms": None, "headers": {}, "body_preview": None,
        "is_json": False, "json_analysis": None, "note": None, "error": None,
    }
    try:
        async with httpx.AsyncClient(headers=req_headers, follow_redirects=True, timeout=15) as client:
            kwargs = {}
            if body and method in ("POST", "PUT", "PATCH", "DELETE"):
                kwargs["content"] = body
            resp = await client.request(method, url, **kwargs)
    except Exception as exc:
        result["error"] = str(exc)
        return result

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    result["status_code"] = resp.status_code
    result["elapsed_ms"] = elapsed_ms
    result["headers"] = dict(resp.headers)
    result["final_url"] = str(resp.url)
    result["redirect_chain"] = [
        {"status_code": h.status_code, "from_url": str(h.url), "location": h.headers.get("location")}
        for h in resp.history
    ]

    ct = resp.headers.get("content-type", "")
    raw_text = resp.text[:20_000]  # limite de segurança para não devolver payloads gigantes
    result["body_preview"] = raw_text

    if "json" in ct:
        try:
            resp.json()  # apenas para confirmar que é JSON válido
            result["is_json"] = True
        except Exception:
            pass

    # extração de PII/secrets/JWT roda sobre qualquer corpo de texto (JSON,
    # HTML de erro, texto simples, etc.), não só quando content-type é JSON —
    # respostas de erro ou páginas de fallback também podem vazar dados.
    if raw_text and (result["is_json"] or _is_probably_text_body(ct)):
        result["json_analysis"] = _analyze_response_text(raw_text)

    # nota sobre método aparentemente habilitado quando 400 em métodos de escrita
    if method in ("POST", "PUT", "PATCH", "DELETE") and resp.status_code == 400:
        result["note"] = (
            "O método retornou 400 Bad Request — isto sugere que o método está "
            "habilitado na rota e provavelmente só requer parâmetros/corpo válidos. "
            "Isto não confirma, por si só, uma vulnerabilidade."
        )

    return result


async def infer_http_methods(url: str, headers: dict | None = None) -> dict:
    """Quando o servidor não expõe (ou não responde de forma útil a) OPTIONS,
    infere quais métodos parecem habilitados testando cada um e observando o
    código de status devolvido, em vez de assumir com base num único pedido."""
    req_headers = build_headers(headers)
    result = {"url": url, "via_options": False, "allow_header": None, "methods": {}}

    async with httpx.AsyncClient(headers=req_headers, follow_redirects=True, timeout=15) as client:
        try:
            opt_resp = await client.request("OPTIONS", url)
            allow = opt_resp.headers.get("allow")
            if allow:
                result["via_options"] = True
                result["allow_header"] = allow
                allowed = {m.strip().upper() for m in allow.split(",")}
                for m in PROBE_METHODS + ["HEAD", "OPTIONS"]:
                    result["methods"][m] = {
                        "status_code": None,
                        "inference": "enabled" if m in allowed else "disabled",
                        "source": "Allow header (OPTIONS)",
                    }
                return result
        except Exception:
            pass

        # OPTIONS indisponível/sem Allow útil -> inferência por tentativa,
        # comparando os códigos de status devolvidos por cada método.
        async def probe(m):
            try:
                r = await client.request(m, url)
                status = r.status_code
                if status in METHOD_ENABLED_STATUS_HINTS["likely_enabled"]:
                    inference = "likely_enabled"
                elif status in METHOD_ENABLED_STATUS_HINTS["likely_disabled"]:
                    inference = "likely_disabled"
                else:
                    inference = "inconclusive"
                return m, {"status_code": status, "inference": inference, "source": "sondagem direta"}
            except Exception as exc:
                return m, {"status_code": None, "inference": "error", "source": str(exc)}

        pairs = await asyncio.gather(*(probe(m) for m in PROBE_METHODS))
        result["methods"] = {m: info for m, info in pairs}

    return result