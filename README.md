# Recon Tool — Reconhecimento Passivo

Ferramenta didática para automatizar a fase de *Information Gathering* em
auditorias **autorizadas** de aplicações web. Realiza apenas leitura estática
de recursos públicos (HTML, JS, CSS, headers, robots.txt, sitemap, Swagger).
Não explora vulnerabilidades, não faz força bruta nem altera o estado do alvo.

## Estrutura

```
reconapp/
├── backend/          FastAPI + SQLite + SSE
│   ├── main.py
│   ├── analyzer.py
│   ├── patterns.py
│   ├── database.py
│   └── requirements.txt
└── frontend/
    └── index.html     Interface single-page (Tailwind via CDN, JS puro)
```

## 1. Instalar o backend

Requisitos: Python 3.10+ (o pedido original menciona 3.13; qualquer versão ≥3.10 funciona).

```bash
cd reconapp/backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Correr o backend

```bash
uvicorn main:app --reload --port 8000
```

Testa se subiu corretamente:

```bash
curl http://localhost:8000/api/health
# {"status":"ok"}
```

A documentação interativa da API fica automaticamente disponível em:
`http://localhost:8000/docs`

## 3. Abrir o frontend

Não precisa de build. Basta abrir o ficheiro no browser:

```bash
open reconapp/frontend/index.html      # macOS
xdg-open reconapp/frontend/index.html  # Linux
# ou simplesmente arrasta o ficheiro para o browser
```

Se o browser bloquear `fetch` por causa de `file://`, serve a pasta com um
servidor estático simples:

```bash
cd reconapp/frontend
python3 -m http.server 5173
# depois abre http://localhost:5173
```

O CORS já está liberado (`*`) no backend para facilitar testes locais.

## 4. Testar uma análise

1. Com o backend a correr (`uvicorn main:app --reload --port 8000`) e o
   frontend aberto no browser.
2. No campo de URL, insere um alvo que tenhas autorização para testar —
   por exemplo uma app tua própria em `http://localhost:3000`, ou um site
   de teste público como `https://example.com`.
3. Clica **Analisar** e acompanha a barra de progresso (Fingerprint →
   Download → Parsing → PII/Secrets → Estatísticas).
4. Explora as abas: Resumo, Tecnologias, Headers, Cookies, JavaScript,
   Endpoints, Swagger, Env Vars, Secrets, JWT, Storage, PII, URLs Externas.
5. Usa a pesquisa global para procurar por termos como `token`, `api`,
   `password`, `email`.
6. Exporta o relatório em JSON, Markdown, CSV ou HTML pelos botões no fundo.

Também podes testar a API diretamente sem o frontend:

```bash
# iniciar análise
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
# devolve {"job_id": "..."}

# acompanhar progresso (Server-Sent Events)
curl -N http://localhost:8000/api/analyze/<job_id>/stream

# obter relatório final
curl http://localhost:8000/api/analyze/<job_id>/report | python3 -m json.tool

# exportar em markdown
curl http://localhost:8000/api/analyze/<job_id>/export?fmt=markdown
```

Os ficheiros baixados de cada análise (HTML, JS, CSS, source maps,
Swagger, relatório JSON) ficam guardados em
`backend/storage/<host>_<id>/`.

## 5. Notas sobre o escopo desta implementação

Esta é uma base funcional cobrindo o núcleo do fluxo pedido: fingerprint,
headers/cookies, descoberta e download de JS (incluindo source maps),
parsing de chamadas HTTP/GraphQL/WebSocket, descoberta de Swagger/OpenAPI,
extração de variáveis de ambiente, secrets (heurísticas por regex), JWT
(decodificação de header/payload), uso de localStorage/sessionStorage,
PII (heurísticas por regex) e domínios externos, com progresso em tempo
real via SSE, persistência em SQLite, pesquisa global e exportação em
4 formatos.

Pontos que ficaram simplificados de propósito, para manteres controlo total
sobre o comportamento de rede em auditorias reais:

- **Wappalyzer**: o `requirements.txt` inclui `python-Wappalyzer`, mas o
  fingerprint atual usa heurísticas próprias (headers, meta tags, marcadores
  de HTML) para evitar dependência de um fingerprint database externo que
  pode ficar desatualizado. Dá para trocar por chamadas à lib facilmente em
  `analyzer.py::_fingerprint`.
- **Listagem de diretórios `/_next/static/chunks/`**: não é assumida —
  o crawler só segue `<script src>` e `<link href>` realmente presentes no
  HTML, para não gerar tráfego de enumeração fora do que a própria página
  já expõe.
- **Regras de secrets/PII são heurísticas**: espera falsos positivos;
  o objetivo é reduzir trabalho manual, não substituir revisão humana.
- **Limite de segurança**: no máximo 40 ficheiros JS e 2MB por ficheiro por
  análise, para não sobrecarregar o alvo — ajustável em `analyzer.py`
  (`MAX_JS_FILES`, `MAX_FILE_BYTES`).

Sempre confirma que tens autorização explícita antes de apontar esta
ferramenta a qualquer alvo que não seja teu.

## 6. Melhorias (afinação de padrões e falsos positivos)

- **Secrets/env em bundles minificados**: além de `process.env.X`, agora
  também é detectado o padrão comum em bundles webpackados onde `process` é
  reatribuído a um alias curto (ex.: `i.default.env.GOV_API_USERNAME||"..."`).
  Também é sinalizada a construção client-side de Basic Auth
  (`Buffer.from(\`${u}:${p}\`).toString("base64")`), que indica duas
  variáveis próximas no código provavelmente contendo credenciais.
- **Mapeamento de rotas de frontend**: rotas definidas como "route builders"
  (`chave:()=>"/caminho"` ou `chave:e=>\`/caminho/${e}/editar\``, comuns em
  apps Next.js/React minificadas) agora são extraídas e combinadas com o
  domínio raiz do alvo, aparecendo na nova aba **ROTAS** com botão para
  executar GET diretamente.
- **Mapeamento de APIs relativas**: chamadas em clientes HTTP renomeados
  (ex.: `s.api.get("v1/applicants")`, `s.default.get("https://...")`) são
  detectadas mesmo sem o literal "axios". Quando o path é relativo (sem `/`
  inicial), o sistema gera candidatos plausíveis (`/api/v1/...` e `/v1/...`)
  para o utilizador escolher/testar, já que o baseURL real só existe em
  runtime.
- **PII/secrets em respostas de endpoints**: a varredura automática ao
  executar um método numa rota/API descoberta agora roda sobre qualquer
  corpo de texto (não só JSON) — respostas de erro, HTML ou texto simples
  também podem vazar emails e outras PII.
- **Menos falsos positivos no Swagger/OpenAPI**: antes, qualquer path de
  `API_DOC_PATHS` que devolvesse 200 era marcado como "encontrado" — o que
  gerava falsos positivos constantes em SPAs com catch-all (React
  Router/Next.js servindo o mesmo `index.html` para qualquer rota). Agora o
  conteúdo é validado (chaves `swagger`/`openapi`+`paths` em JSON,
  marcadores como `swagger-ui`/`redoc` em HTML) antes de confirmar um
  achado; achados não confirmados aparecem separadamente com uma nota.
- **robots.txt e sitemap.xml**: diretivas `Disallow`/`Allow`/`Sitemap` de
  `robots.txt` e URLs `<loc>` de `sitemap.xml` agora são extraídas e
  listadas na nova aba **ROBOTS.TXT**, como candidatos adicionais de rotas
  para inspeção manual.
