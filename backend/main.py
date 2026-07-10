import asyncio
import csv
import io
import json
import uuid
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from analyzer import ReconAnalyzer, ProgressReporter, execute_probe, infer_http_methods
from database import init_db, get_session, Job

app = FastAPI(title="Recon Tool API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# job_id -> asyncio.Queue (fila de eventos de progresso em memória)
JOB_QUEUES: dict[str, asyncio.Queue] = {}


class AnalyzeRequest(BaseModel):
    url: str
    headers: dict[str, str] | None = None
    options: dict[str, bool] | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("URL inválida. Use o formato https://exemplo.com")
        return v


class ProbeRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    body: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("URL inválida.")
        return v


class MethodsRequest(BaseModel):
    url: str
    headers: dict[str, str] | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("URL inválida.")
        return v


@app.post("/api/analyze")
async def start_analyze(req: AnalyzeRequest):
    job_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    JOB_QUEUES[job_id] = queue

    session = get_session()
    job = Job(id=job_id, target_url=req.url, status="running")
    session.add(job)
    session.commit()
    session.close()

    asyncio.create_task(_run_analysis(job_id, req.url, req.headers, req.options, queue))
    return {"job_id": job_id}


@app.post("/api/probe")
async def probe_endpoint(req: ProbeRequest):
    """Executa, a pedido explícito do utilizador a partir do frontend, uma
    requisição a um endpoint descoberto (ou qualquer URL) com o método e
    headers escolhidos, e devolve status/tempo/corpo + análise de JSON."""
    try:
        return await execute_probe(req.url, req.method, req.headers, req.body)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/probe/methods")
async def probe_methods(req: MethodsRequest):
    """Infere quais métodos HTTP a rota aceita, via OPTIONS quando
    disponível, ou por sondagem direta caso contrário."""
    return await infer_http_methods(req.url, req.headers)


async def _run_analysis(job_id: str, url: str, headers: dict | None, options: dict | None, queue: asyncio.Queue):
    progress = ProgressReporter(queue)
    session = get_session()
    try:
        analyzer = ReconAnalyzer(url, progress, custom_headers=headers, options=options)
        report = await analyzer.run()
        job = session.get(Job, job_id)
        job.status = "done"
        job.report_json = json.dumps(report, ensure_ascii=False)
        session.commit()
    except Exception as exc:
        job = session.get(Job, job_id)
        if job:
            job.status = "error"
            job.error_message = str(exc)
            session.commit()
        await queue.put({"stage": "error", "message": f"Erro: {exc}", "percent": 100, "data": {}})
    finally:
        await queue.put(None)  # sinaliza fim do stream
        session.close()


@app.get("/api/analyze/{job_id}/stream")
async def stream_progress(job_id: str):
    queue = JOB_QUEUES.get(job_id)
    if queue is None:
        raise HTTPException(404, "Job não encontrado ou já finalizado.")

    async def event_generator():
        while True:
            item = await queue.get()
            if item is None:
                yield "event: end\ndata: {}\n\n"
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
        JOB_QUEUES.pop(job_id, None)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/analyze/{job_id}/report")
async def get_report(job_id: str):
    session = get_session()
    job = session.get(Job, job_id)
    session.close()
    if job is None:
        raise HTTPException(404, "Job não encontrado.")
    return {
        "job_id": job.id,
        "target_url": job.target_url,
        "status": job.status,
        "error_message": job.error_message,
        "report": job.report(),
    }


@app.get("/api/jobs")
async def list_jobs():
    session = get_session()
    jobs = session.query(Job).order_by(Job.created_at.desc()).limit(50).all()
    session.close()
    return [
        {"job_id": j.id, "target_url": j.target_url, "status": j.status,
         "created_at": j.created_at.isoformat() if j.created_at else None}
        for j in jobs
    ]


@app.get("/api/analyze/{job_id}/search")
async def search_report(job_id: str, q: str):
    session = get_session()
    job = session.get(Job, job_id)
    session.close()
    if job is None or job.report() is None:
        raise HTTPException(404, "Relatório não encontrado.")

    report = job.report()
    q_lower = q.lower()
    results = []

    def scan(section_name, items):
        for item in items:
            blob = json.dumps(item, ensure_ascii=False).lower()
            if q_lower in blob:
                results.append({"section": section_name, "item": item})

    for section in ["endpoints", "routes", "secrets", "jwts", "cookies", "pii",
                    "env_vars", "external_domains", "api_docs", "js_files",
                    "robots_findings", "sitemap_urls"]:
        value = report.get(section, [])
        if isinstance(value, list):
            if value and isinstance(value[0], str):
                scan(section, [{"value": v} for v in value if q_lower in v.lower()])
            else:
                scan(section, value)

    return {"query": q, "results": results, "count": len(results)}


@app.get("/api/analyze/{job_id}/export")
async def export_report(job_id: str, fmt: str = "json"):
    session = get_session()
    job = session.get(Job, job_id)
    session.close()
    if job is None or job.report() is None:
        raise HTTPException(404, "Relatório não encontrado.")

    report = job.report()

    if fmt == "json":
        return PlainTextResponse(json.dumps(report, ensure_ascii=False, indent=2),
                                  media_type="application/json")

    if fmt == "markdown":
        md = _report_to_markdown(report)
        return PlainTextResponse(md, media_type="text/markdown")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["section", "field", "value"])
        for section in ["endpoints", "routes", "secrets", "jwts", "cookies", "pii",
                        "env_vars", "external_domains", "robots_findings"]:
            for item in report.get(section, []):
                if isinstance(item, dict):
                    writer.writerow([section, "", json.dumps(item, ensure_ascii=False)])
                else:
                    writer.writerow([section, "", item])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")

    if fmt == "html":
        md = _report_to_markdown(report)
        html = f"<html><head><meta charset='utf-8'><title>Relatório</title></head><body><pre>{md}</pre></body></html>"
        return PlainTextResponse(html, media_type="text/html")

    raise HTTPException(400, "Formato não suportado. Use json, markdown, csv ou html.")


def _report_to_markdown(report: dict) -> str:
    lines = [f"# Relatório de Reconhecimento — {report.get('target')}", ""]
    if report.get("final_url") and report["final_url"] != report.get("target"):
        lines.append(f"**Destino final após redirecionamentos:** {report['final_url']}\n")
    lines.append("## Resumo Estatístico")
    for k, v in report.get("stats", {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("\n## Tecnologias Detectadas")
    tech_details = report.get("technologies_detail") or [
        {"name": n, "confirmed_files": []} for n in report.get("technologies", [])
    ]
    for t in tech_details:
        confirmed = ", ".join(f["path"] for f in t.get("confirmed_files", []))
        lines.append(f"- {t['name']}" + (f" (confirmado via: {confirmed})" if confirmed else ""))
    lines.append("\n## Endpoints Descobertos")
    for e in report.get("endpoints", []):
        candidates = e.get("candidate_urls") or []
        cand_note = f" — candidatos: {', '.join(candidates)}" if len(candidates) > 1 else ""
        lines.append(f"- `{'/'.join(e['methods'])}` {e['path']} (módulo: {e['module']}){cand_note}")
    lines.append("\n## Rotas de Frontend Descobertas")
    for r in report.get("routes", []):
        param_note = " (com parâmetro)" if r.get("has_param") else ""
        lines.append(f"- {r['full_url']}{param_note} (chave: {', '.join(r.get('keys', []))})")
    lines.append("\n## Secrets Identificados")
    for s in report.get("secrets", []):
        lines.append(f"- [{s.get('relevance', '?')}] {s['type']}: `{s['match_preview']}` "
                      f"(fonte: {s.get('source_type', '?')} — {s['source_file']})")
    lines.append("\n## JWTs")
    for j in report.get("jwts", []):
        lines.append(f"- {j['token_preview']} — alg: {j['header'].get('alg')}, "
                      f"exp: {j['payload'].get('exp')} (fonte: {j.get('source_file')})")
    lines.append("\n## Cookies")
    for c in report.get("cookies", []):
        lines.append(f"- {c['name']} (HttpOnly={c['http_only']}, Secure={c['secure']}, "
                      f"SameSite={c['same_site']})")
    lines.append("\n## PII Identificada")
    for p in report.get("pii", []):
        lines.append(f"- [{p.get('relevance', '?')}] {p['type']}: {p['value']} (fonte: {p.get('source_file')})")
    lines.append("\n## Domínios Externos")
    for d in report.get("external_domains", []):
        lines.append(f"- {d}")
    lines.append("\n## Swagger/OpenAPI")
    for a in report.get("api_docs", []):
        status_tag = "confirmado" if a.get("confirmed") else "NÃO confirmado (possível falso positivo)"
        lines.append(f"- [{status_tag}] {a['url']} (status {a['status_code']})")
    lines.append("\n## robots.txt")
    for rb in report.get("robots_findings", []):
        lines.append(f"- {rb['directive']}: {rb['full_url']}")
    if report.get("sitemap_urls"):
        lines.append("\n## sitemap.xml")
        for su in report.get("sitemap_urls", []):
            lines.append(f"- {su}")
    return "\n".join(lines)


@app.get("/api/health")
async def health():
    return {"status": "ok"}