"""
Motor de reconhecimento passivo.

Todas as operações de rede aqui feitas são pedidos HTTP GET/HEAD de leitura,
sobre recursos públicos do próprio alvo informado pelo utilizador
(HTML, JS, CSS, robots.txt, sitemap.xml, source maps, Swagger/OpenAPI).
Não é efetuada qualquer tentativa de exploração, força bruta,
bypass de autenticação ou modificação de estado da aplicação alvo.
"""
import asyncio
import base64
import json
import os
import re
import uuid
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from patterns import (
    HTTP_CALL_PATTERNS, GENERIC_PATH_PATTERN, ABSOLUTE_URL_PATTERN,
    API_DOC_PATHS, STATIC_TARGETS, ENV_VAR_PATTERN, PROCESS_ENV_PATTERN,
    IMPORT_META_ENV_PATTERN, SECRET_PATTERNS, JWT_PATTERN, JWT_USAGE_HINTS,
    STORAGE_USAGE_PATTERN, PII_PATTERNS, KNOWN_THIRD_PARTY_DOMAINS,
    SECURITY_HEADERS,
)

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
MAX_JS_FILES = 40          # limite de segurança para não sobrecarregar o alvo
MAX_FILE_BYTES = 2_000_000  # 2MB por ficheiro


def _safe_dir_name(url: str) -> str:
    host = urlparse(url).netloc.replace(":", "_")
    return f"{host}_{uuid.uuid4().hex[:8]}"


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


class ReconAnalyzer:
    def __init__(self, target_url: str, progress: ProgressReporter):
        self.target_url = target_url.rstrip("/")
        self.progress = progress
        self.parsed = urlparse(self.target_url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.job_dir = os.path.join(STORAGE_DIR, _safe_dir_name(self.target_url))
        os.makedirs(self.job_dir, exist_ok=True)

        self.report = {
            "target": self.target_url,
            "technologies": [],
            "http": {},
            "cookies": [],
            "files_downloaded": [],
            "js_files": [],
            "endpoints": [],
            "api_docs": [],
            "env_vars": [],
            "secrets": [],
            "jwts": [],
            "storage_usage": [],
            "pii": [],
            "external_domains": [],
            "modules": [],
            "stats": {},
        }

    # ------------------------------------------------------------------
    async def run(self) -> dict:
        async with httpx.AsyncClient(headers={"User-Agent": "ReconTool/1.0 (auditoria autorizada)"}) as client:
            await self.progress.emit("fingerprint", "Detectando tecnologias e cabeçalhos HTTP...", 5)
            html_text = await self._fingerprint(client)

            await self.progress.emit("static", "Baixando recursos estáticos (robots, sitemap, manifest)...", 15)
            await self._download_static(client)

            await self.progress.emit("discovery", "Descobrindo arquivos JavaScript...", 25)
            js_urls = await self._discover_js(client, html_text)

            await self.progress.emit("download", "Baixando arquivos JavaScript...", 35, {"total": len(js_urls)})
            js_contents = await self._download_js(client, js_urls)

            await self.progress.emit("parsing", "Analisando arquivos JavaScript...", 55)
            self._parse_js(js_contents)

            await self.progress.emit("apidocs", "Procurando documentação de API (Swagger/OpenAPI)...", 70)
            await self._discover_api_docs(client)

            await self.progress.emit("pii", "Extraindo PII, secrets e tokens...", 85)
            self._extract_pii_and_secrets(html_text, js_contents)

            await self.progress.emit("stats", "Gerando estatísticas finais...", 95)
            self._compute_stats()

            await self.progress.emit("done", "Análise concluída.", 100)
            self._save_report_file()
            return self.report

    # ------------------------------------------------------------------
    async def _fingerprint(self, client: httpx.AsyncClient) -> str:
        resp = await _get(client, self.target_url)
        html_text = ""
        if resp is not None:
            html_text = resp.text
            headers = dict(resp.headers)
            self.report["http"] = {
                "status_code": resp.status_code,
                "headers": headers,
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "content_type": headers.get("content-type"),
                "cache_control": headers.get("cache-control"),
                "etag": headers.get("etag"),
                "security_headers": {
                    h: headers.get(h) for h in SECURITY_HEADERS if h in {k.lower() for k in headers}
                },
            }
            self.report["cookies"] = self._parse_cookies(resp)
            self._save_file("index.html", html_text)
            self.report["files_downloaded"].append("index.html")

            techs = set()
            server = (headers.get("server") or "").lower()
            powered = (headers.get("x-powered-by") or "").lower()
            if "cloudflare" in server:
                techs.add("Cloudflare")
            if "nginx" in server:
                techs.add("Nginx")
            if "apache" in server:
                techs.add("Apache")
            if "iis" in server:
                techs.add("IIS")
            if "express" in powered:
                techs.add("Express")
            if "asp.net" in powered or "asp.net" in server:
                techs.add("ASP.NET")
            if "php" in powered:
                techs.add("PHP")

            soup = BeautifulSoup(html_text, "html.parser")
            if soup.find(id="__next") or "/_next/static" in html_text:
                techs.add("Next.js")
            if soup.find(id="root") and "/static/js/" in html_text:
                techs.add("React")
            if "ng-version" in html_text or soup.find(attrs={"ng-version": True}):
                techs.add("Angular")
            if "vue" in html_text.lower() and "/assets/" in html_text:
                techs.add("Vue")
            if "supabase" in html_text.lower():
                techs.add("Supabase")
            if "firebase" in html_text.lower():
                techs.add("Firebase")
            for meta in soup.find_all("meta"):
                if meta.get("name") == "generator" and meta.get("content"):
                    techs.add(meta["content"])

            self.report["technologies"] = sorted(techs)
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
            }
            cookies.append(entry)
        return cookies

    # ------------------------------------------------------------------
    async def _download_static(self, client: httpx.AsyncClient):
        for path in STATIC_TARGETS:
            url = urljoin(self.base + "/", path.lstrip("/"))
            resp = await _get(client, url)
            if resp is not None and resp.status_code == 200:
                fname = path.lstrip("/").replace("/", "_")
                self._save_file(fname, resp.text if self._is_text(resp) else "")
                self.report["files_downloaded"].append(fname)

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

        # heurística Next.js: procurar build manifest
        if "/_next/static/" in html_text:
            resp = await _get(client, urljoin(self.base + "/", "_next/static/chunks/"))
            # normalmente 404/403 (listagem de diretório desativada); mantemos
            # apenas os scripts já referenciados no HTML nesse caso.

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
        env_vars = set()
        modules = set()

        for url, content in js_contents.items():
            # chamadas fetch/axios/xhr/websocket
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

            # variáveis de ambiente
            for pattern in (ENV_VAR_PATTERN, PROCESS_ENV_PATTERN, IMPORT_META_ENV_PATTERN):
                for m in pattern.finditer(content):
                    env_vars.add(m.group(1) if m.lastindex else m.group(0))

            # JWTs
            for m in JWT_PATTERN.finditer(content):
                token = m.group(0)
                decoded = _decode_jwt(token)
                if decoded:
                    self.report["jwts"].append({
                        "token_preview": token[:24] + "...",
                        "header": decoded["header"],
                        "payload": decoded["payload"],
                        "source_file": url,
                    })

            # uso de storage
            for m in STORAGE_USAGE_PATTERN.finditer(content):
                self.report["storage_usage"].append({
                    "api": m.group(1),
                    "method": m.group(2),
                    "key": m.group(3),
                    "source_file": url,
                })

            # domínios externos
            for m in ABSOLUTE_URL_PATTERN.finditer(content):
                domain = urlparse(m.group(0)).netloc
                if domain and domain != self.parsed.netloc:
                    modules.add(domain)

        for path, info in endpoints.items():
            module = _classify_module(path)
            self.report["endpoints"].append({
                "path": path,
                "methods": sorted(info["methods"]),
                "module": module,
                "sources": sorted(info["sources"]),
            })

        self.report["env_vars"] = sorted(env_vars)
        self.report["external_domains"] = sorted(modules)
        self.report["modules"] = sorted({e["module"] for e in self.report["endpoints"]})

    @staticmethod
    def _register_endpoint(endpoints: dict, method: str, path: str, source: str):
        if not path or len(path) > 300:
            return
        entry = endpoints.setdefault(path, {"methods": set(), "sources": set()})
        entry["methods"].add(method)
        entry["sources"].add(source)

    # ------------------------------------------------------------------
    async def _discover_api_docs(self, client: httpx.AsyncClient):
        for path in API_DOC_PATHS:
            url = urljoin(self.base + "/", path.lstrip("/"))
            resp = await _get(client, url)
            if resp is not None and resp.status_code == 200:
                entry = {"path": path, "url": url, "status_code": resp.status_code}
                ct = resp.headers.get("content-type", "")
                if "json" in ct or path.endswith(".json"):
                    try:
                        spec = resp.json()
                        entry["endpoints_count"] = len(spec.get("paths", {}))
                        entry["title"] = spec.get("info", {}).get("title")
                    except Exception:
                        pass
                self.report["api_docs"].append(entry)
                fname = re.sub(r"[^a-zA-Z0-9_.-]", "_", path.lstrip("/")) or "apidoc"
                self._save_file(fname, resp.text if self._is_text(resp) else "")

    # ------------------------------------------------------------------
    def _extract_pii_and_secrets(self, html_text: str, js_contents: dict[str, str]):
        all_texts = {"index.html": html_text, **js_contents}
        seen_secrets = set()
        seen_pii = set()

        for source, text in all_texts.items():
            if not text:
                continue
            for name, pattern in SECRET_PATTERNS.items():
                for m in pattern.finditer(text):
                    value = m.group(0)
                    key = (name, value)
                    if key in seen_secrets:
                        continue
                    seen_secrets.add(key)
                    self.report["secrets"].append({
                        "type": name,
                        "match_preview": value[:60] + ("..." if len(value) > 60 else ""),
                        "source_file": source,
                    })

            for name, pattern in PII_PATTERNS.items():
                for m in pattern.finditer(text):
                    value = m.group(0)
                    key = (name, value)
                    if key in seen_pii:
                        continue
                    seen_pii.add(key)
                    self.report["pii"].append({
                        "type": name,
                        "value": value,
                        "source_file": source,
                    })

    # ------------------------------------------------------------------
    def _compute_stats(self):
        r = self.report
        r["stats"] = {
            "js_files": len(r["js_files"]),
            "endpoints": len(r["endpoints"]),
            "external_domains": len(r["external_domains"]),
            "api_docs": len(r["api_docs"]),
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
