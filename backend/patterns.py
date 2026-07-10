"""
Coleção centralizada de expressões regulares e tabelas de referência usadas
na análise estática e nas sondagens de reconhecimento (fingerprint de stack,
inferência de métodos HTTP, etc.).

Todas as extrações continuam a operar apenas sobre texto/HTTP obtido através
de pedidos de leitura (GET/HEAD/OPTIONS) contra o alvo informado pelo
utilizador, ou pedidos explicitamente disparados por ele a partir do
frontend ("Executar" num endpoint descoberto).
"""
import re

# ---------------------------------------------------------------------------
# User-Agent legítimo de navegador — usado por omissão em todas as
# requisições, para que o alvo não trate o tráfego como bot/scanner.
# Pode ser substituído pelo utilizador via headers customizados.
# ---------------------------------------------------------------------------
DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

DEFAULT_BROWSER_HEADERS = {
    "User-Agent": DEFAULT_BROWSER_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7",
}

# Headers que nunca devem ser sobrepostos por input do utilizador (segurança
# de transporte / roteamento do próprio pedido) — todos os outros
# (Authorization, Cookie, X-..., etc.) podem ser customizados livremente.
RESERVED_HEADERS = {"host", "content-length", "connection"}

# ---------------------------------------------------------------------------
# Chamadas de rede em JavaScript (fetch, axios, XHR, WebSocket, GraphQL)
# ---------------------------------------------------------------------------
HTTP_CALL_PATTERNS = {
    "fetch": re.compile(r"fetch\(\s*[`'\"]([^`'\"]+)[`'\"]"),
    "axios": re.compile(r"axios\.(get|post|put|patch|delete|head|options)\(\s*[`'\"]([^`'\"]+)[`'\"]", re.I),
    "xhr_open": re.compile(r"\.open\(\s*[`'\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[`'\"]\s*,\s*[`'\"]([^`'\"]+)[`'\"]", re.I),
    "websocket": re.compile(r"new\s+WebSocket\(\s*[`'\"]([^`'\"]+)[`'\"]"),
    "graphql_endpoint": re.compile(r"[`'\"](/?[\w\-./]*graphql[\w\-./]*)[`'\"]", re.I),
}

# Qualquer caminho tipo /api/... ou URL absoluta dentro de strings JS
GENERIC_PATH_PATTERN = re.compile(r"""[`'"](/(?:api|rest|graphql|v[0-9]+)[a-zA-Z0-9_\-/.{}]*)['"`]""")
ABSOLUTE_URL_PATTERN = re.compile(r"""https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9_\-./?%&=#{}\[\]]*)?""")

# ---------------------------------------------------------------------------
# Chamadas HTTP em bundles minificados/webpackados, onde o cliente HTTP
# (axios, wrapper próprio, etc.) chega renomeado/encadeado por trás de um
# identificador curto — ex.: `s.default.get("https://...")`,
# `s.api.get("v1/applicants")`, `n.default.post(\`/x/${e}\`)`.
# Diferente de HTTP_CALL_PATTERNS["axios"], não depende do literal "axios".
# O filtro sobre se o path parece mesmo uma rota de API (e não Map.get() etc.)
# é feito em analyzer.py::_looks_like_api_path.
# ---------------------------------------------------------------------------
GENERIC_CLIENT_CALL_PATTERN = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})\.(get|post|put|patch|delete)\(\s*"
    r"[`'\"]([^`'\"]+)[`'\"]", re.I
)

# ---------------------------------------------------------------------------
# Rotas de frontend definidas como objetos de "route builders" — muito comum
# em apps Next.js/React minificadas: `chave:()=>"/caminho"` (sem parâmetro) ou
# `chave:e=>\`/caminho/${e}/editar\`` (com parâmetro interpolado).
# ---------------------------------------------------------------------------
ROUTE_ARROW_LITERAL_PATTERN = re.compile(
    r"([A-Za-z_$][\w$]*)\s*:\s*\(\)\s*=>\s*[`'\"](/[a-zA-Z0-9_\-./{}]*)[`'\"]"
)
ROUTE_ARROW_TEMPLATE_PATTERN = re.compile(
    r"([A-Za-z_$][\w$]*)\s*:\s*[A-Za-z_$][\w$]*\s*=>\s*`(/[a-zA-Z0-9_\-./{}$]*\$\{[^`]*?\}[a-zA-Z0-9_\-./{}$]*)`"
)

# Correlação: base URLs configuradas em clientes HTTP
# ex.: axios.create({ baseURL: "https://api.exemplo.com" })
AXIOS_CREATE_BASEURL_PATTERN = re.compile(
    r"axios\.create\(\s*\{[^}]*?baseURL\s*:\s*[`'\"]([^`'\"]+)[`'\"]", re.S
)
# ex.: const API_URL = "https://api.exemplo.com"; const API = process.env.X || "...";
CONST_URL_ASSIGNMENT_PATTERN = re.compile(
    r"(?:const|let|var)\s+([A-Za-z0-9_]*(?:API|URL|ENDPOINT|BASE|HOST)[A-Za-z0-9_]*)\s*=\s*"
    r"(?:process\.env\.[A-Za-z0-9_]+\s*\|\|\s*)?[`'\"]([^`'\"]+)[`'\"]", re.I
)

# ---------------------------------------------------------------------------
# Documentação de API
# ---------------------------------------------------------------------------
API_DOC_PATHS = [
    "/api", "/api/v1", "/graphql", "/rest",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger", "/swagger-ui", "/swagger-ui/index.html",
    "/api-docs", "/docs", "/redoc",
]

STATIC_TARGETS = ["/manifest.json", "/robots.txt", "/sitemap.xml", "/favicon.ico"]

# ---------------------------------------------------------------------------
# Arquivos característicos por stack — sondados automaticamente assim que a
# tecnologia é detectada por heurística (headers/HTML/meta tags).
# ---------------------------------------------------------------------------
STACK_FINGERPRINT_FILES = {
    "Next.js": [
        "/_next/static/chunks/webpack.js",
        "/_next/static/development/_buildManifest.js",
        "/_next/app-build-manifest.json",
        "/_next/static/chunks/main.js",
        "/next.config.js",
    ],
    "React": [
        "/asset-manifest.json",
        "/static/js/main.js",
    ],
    "Angular": [
        "/main.js",
        "/runtime.js",
        "/polyfills.js",
        "/assets/config.json",
    ],
    "Vue": [
        "/vue.config.js",
        "/assets/index.js",
    ],
    "Nuxt.js": [
        "/_nuxt/",
        "/__nuxt.js",
    ],
    "Laravel": [
        "/.env",
        "/mix-manifest.json",
        "/storage/logs/laravel.log",
        "/vendor/composer/installed.json",
        "/artisan",
        "/telescope",
        "/horizon",
    ],
    "ASP.NET": [
        "/web.config",
        "/elmah.axd",
        "/Global.asax",
        "/Trace.axd",
        "/bin/",
    ],
    "Django": [
        "/static/admin/css/base.css",
        "/admin/login/",
        "/__debug__/",
    ],
    "Ruby on Rails": [
        "/assets/application.js",
        "/rails/info/properties",
    ],
    "WordPress": [
        "/wp-json/",
        "/wp-login.php",
        "/wp-content/",
        "/xmlrpc.php",
    ],
    "Spring Boot": [
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/beans",
    ],
}

# ---------------------------------------------------------------------------
# Variáveis de ambiente expostas no bundle do cliente
# ---------------------------------------------------------------------------
ENV_VAR_PATTERN = re.compile(
    r"\b(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+)\b"
)
PROCESS_ENV_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+)")
IMPORT_META_ENV_PATTERN = re.compile(r"import\.meta\.env\.([A-Za-z0-9_]+)")

# Correlação: process.env.X || "valor_fallback" — captura o fallback embutido
# no bundle, que é frequentemente uma credencial/URL real esquecida no código.
ENV_FALLBACK_PATTERN = re.compile(
    r"process\.env\.([A-Z0-9_]+)\s*\|\|\s*[`'\"]([^`'\"]{3,})[`'\"]"
)

# Em bundles minificados/webpackados, `process` é frequentemente reatribuído
# a um identificador curto (ex.: `i.default.env.GOV_API_USERNAME`, em vez de
# `process.env.GOV_API_USERNAME`), porque o bundler embrulha o módulo `process`
# do Node e o código transpilado acessa `.default.env.X`. Estes padrões
# generalizam a captura para qualquer alias, não só o literal "process".
ALIASED_ENV_ACCESS_PATTERN = re.compile(
    r"\b[A-Za-z_$][\w$]*(?:\.default)?\.env\.([A-Z][A-Z0-9_]{2,})\b"
)
ALIASED_ENV_FALLBACK_PATTERN = re.compile(
    r"[A-Za-z_$][\w$]*(?:\.default)?\.env\.([A-Z][A-Z0-9_]{2,})\s*\|\|\s*[`'\"]([^`'\"]{2,})[`'\"]"
)

# Construção client-side de credenciais Basic Auth — ex.:
# `Buffer.from(\`${user}:${pass}\`).toString("base64")`. Não captura o valor
# (é montado em runtime), mas sinaliza que duas variáveis próximas no código
# provavelmente contêm usuário/senha embutidos e vale a pena inspecionar
# manualmente as linhas ao redor.
BASIC_AUTH_BUILD_PATTERN = re.compile(
    r"Buffer\.from\(\s*`\$\{[^}]+\}:\$\{[^}]+\}`\s*\)\.toString\(\s*[`'\"]base64[`'\"]\s*\)"
)

# ---------------------------------------------------------------------------
# Secrets / credenciais (heurísticas — falsos positivos são esperados e
# devem ser revistos manualmente antes de qualquer ação)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|access)?[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "firebase_key": re.compile(r"AIzaSy[0-9A-Za-z\-_]{33}"),
    "stripe_key": re.compile(r"(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "twilio_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "generic_bearer": re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]{10,}"),
    "basic_auth": re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_secret_assignment": re.compile(
        r"(?i)(api[_-]?key|secret|client[_-]?secret|client[_-]?id|access[_-]?key|"
        r"refresh[_-]?token|session[_-]?token|password|passwd|authorization)"
        r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_./+=]{6,})['\"]"
    ),
    # Correlação adicional: process.env.X || "valor", const API = "...",
    # axios.create({ baseURL: ... }) capturados genericamente; a relevância
    # final é ajustada em analyzer.py conforme o nome da variável/URL.
    "env_fallback_literal": ENV_FALLBACK_PATTERN,
    "hardcoded_const_url": CONST_URL_ASSIGNMENT_PATTERN,
    "axios_base_url": AXIOS_CREATE_BASEURL_PATTERN,
    "aliased_env_fallback": ALIASED_ENV_FALLBACK_PATTERN,
    "basic_auth_construction": BASIC_AUTH_BUILD_PATTERN,
}

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
JWT_USAGE_HINTS = re.compile(r"\b(jwtDecode|jwt_decode|parseJwt|atob\(token\)|jsonwebtoken)\b")

STORAGE_USAGE_PATTERN = re.compile(
    r"\b(localStorage|sessionStorage|indexedDB|caches)\s*\.\s*(getItem|setItem|open)\s*\(\s*[`'\"]([^`'\"]+)[`'\"]"
)

# Chaves de storage consideradas sensíveis por nome — usadas para elevar a
# relevância do achado mesmo sem conseguir ler o valor real em runtime
# (a análise é estática sobre o código-fonte, não executa o JS num browser).
STORAGE_SENSITIVE_KEYS = [
    "isadmin", "role", "roles", "permission", "permissions", "accesstoken",
    "access_token", "refreshtoken", "refresh_token", "sessionid", "session_id",
    "token", "jwt", "apikey", "api_key", "auth", "secret", "credentials",
]

BASE64_LIKE_PATTERN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
HEX_LIKE_PATTERN = re.compile(r"^[0-9a-fA-F]{16,}$")

# ---------------------------------------------------------------------------
# PII — heurísticas simples, não substituem revisão humana
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "phone_intl": re.compile(r"\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "cpf": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    "nif_pt": re.compile(r"\b[123589]\d{8}\b"),
    "passport_generic": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
}

# Placeholders/dados fictícios comuns — usados para descartar falsos
# positivos de PII (ex.: emails de exemplo em formulários, docs, testes).
PII_PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "email.com", "yoursite.com", "mysite.com", "acme.com", "foo.com",
    "bar.com", "sample.com", "yourcompany.com", "placeholder.com",
}
PII_PLACEHOLDER_LOCAL_PARTS = {
    "test", "teste", "example", "foo", "bar", "user", "admin", "demo",
    "sample", "john.doe", "jane.doe", "name", "email", "your.email",
    "someone", "info", "contact", "no-reply", "noreply", "donotreply",
}
PII_PLACEHOLDER_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
}
PII_PLACEHOLDER_PHONE_PREFIXES = ("+1234", "+0000", "+1111", "+9999")

# Domínios de terceiros comummente encontrados (analytics, CDNs, pagamentos...)
KNOWN_THIRD_PARTY_DOMAINS = [
    "google", "googleapis", "gstatic", "facebook", "fbcdn", "twitter", "x.com",
    "github", "supabase", "firebase", "firebaseio", "amazonaws", "azure",
    "cloudfront", "cloudflare", "stripe", "sentry", "hotjar", "segment",
    "mixpanel", "intercom", "algolia", "vercel", "netlify",
]

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "x-xss-protection", "cross-origin-opener-policy", "cross-origin-resource-policy",
]

# ---------------------------------------------------------------------------
# Relevância — usada para classificar achados (secrets, storage, PII) em
# critical / high / medium / low para priorizar a leitura do relatório.
# ---------------------------------------------------------------------------
SECRET_RELEVANCE = {
    "aws_access_key": "critical",
    "aws_secret_key": "critical",
    "private_key_block": "critical",
    "stripe_key": "critical",
    "github_token": "high",
    "slack_token": "high",
    "twilio_key": "high",
    "google_api_key": "medium",
    "firebase_key": "medium",
    "generic_bearer": "high",
    "basic_auth": "high",
    "generic_secret_assignment": "medium",
    "env_fallback_literal": "medium",
    "hardcoded_const_url": "low",
    "axios_base_url": "low",
    "aliased_env_fallback": "high",
    "basic_auth_construction": "high",
}

PII_RELEVANCE = {
    "email": "medium",
    "phone_intl": "medium",
    "iban": "high",
    "cpf": "high",
    "nif_pt": "high",
    "passport_generic": "high",
    "uuid": "low",
}

# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml — fonte adicional de rotas/áreas que o próprio
# alvo declara (frequentemente inclui painéis administrativos ou áreas que
# o operador queria manter fora de motores de busca, o que não impede a
# ferramenta de as listar como candidatas a reconhecimento).
# ---------------------------------------------------------------------------
ROBOTS_DIRECTIVE_PATTERN = re.compile(
    r"^\s*(Disallow|Allow|Sitemap)\s*:\s*(\S+)\s*$", re.I | re.M
)
SITEMAP_LOC_PATTERN = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# ---------------------------------------------------------------------------
# Validação de Swagger/OpenAPI — usada para descartar falsos positivos comuns
# em SPAs (Next.js/React/Vue Router) que devolvem 200 com o mesmo HTML da
# home para qualquer caminho não mapeado ("catch-all"), o que fazia qualquer
# path de API_DOC_PATHS parecer "encontrado" mesmo quando não existe.
# ---------------------------------------------------------------------------
SWAGGER_JSON_KEYS = ("swagger", "openapi")  # chaves top-level esperadas na spec
SWAGGER_HTML_MARKERS = (
    "swagger-ui", "swaggerui", "swagger ui", "swaggeruibundle",
    "redoc", "spec-url", "openapi.json", "openapi.yaml",
)

# ---------------------------------------------------------------------------
# Inferência de métodos HTTP quando OPTIONS não está disponível/não retorna
# um cabeçalho Allow útil.
# ---------------------------------------------------------------------------
PROBE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
METHOD_ENABLED_STATUS_HINTS = {
    # códigos que indicam que o roteador aceitou/reconheceu o método
    "likely_enabled": {200, 201, 202, 204, 400, 401, 403, 422, 500},
    # códigos que indicam que o método não está implementado na rota
    "likely_disabled": {404, 405, 501},
}