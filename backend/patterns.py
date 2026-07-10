"""
Coleção centralizada de expressões regulares usadas na análise estática.
Todas as extrações aqui são passivas: operam apenas sobre texto já obtido
(HTML/JS/CSS/JSON) através de pedidos GET de leitura.
"""
import re

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
# Documentação de API
# ---------------------------------------------------------------------------
API_DOC_PATHS = [
    "/api", "/api/v1", "/graphql", "/rest",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger", "/swagger-ui", "/swagger-ui/index.html",
    "/api-docs", "/docs", "/redoc",
]

JS_DISCOVERY_HINTS = {
    "nextjs": ["/_next/static/"],
    "react_cra": ["/static/js/"],
    "angular": ["main.", "runtime.", "polyfills."],
    "vue": ["/assets/"],
}

STATIC_TARGETS = ["/manifest.json", "/robots.txt", "/sitemap.xml", "/favicon.ico"]

# ---------------------------------------------------------------------------
# Variáveis de ambiente expostas no bundle do cliente
# ---------------------------------------------------------------------------
ENV_VAR_PATTERN = re.compile(
    r"\b(NEXT_PUBLIC_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|VITE_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+)\b"
)
PROCESS_ENV_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+)")
IMPORT_META_ENV_PATTERN = re.compile(r"import\.meta\.env\.([A-Za-z0-9_]+)")

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
}

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
JWT_USAGE_HINTS = re.compile(r"\b(jwtDecode|jwt_decode|parseJwt|atob\(token\)|jsonwebtoken)\b")

STORAGE_USAGE_PATTERN = re.compile(
    r"\b(localStorage|sessionStorage|indexedDB|caches)\s*\.\s*(getItem|setItem|open)\s*\(\s*[`'\"]([^`'\"]+)[`'\"]"
)

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
