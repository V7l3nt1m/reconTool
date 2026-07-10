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

from analyzer import ReconAnalyzer, ProgressReporter
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

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("URL inválida. Use o formato https://exemplo.com")
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

    asyncio.create_task(_run_analysis(job_id, req.url, queue))
    return {"job_id": job_id}


async def _run_analysis(job_id: str, url: str, queue: asyncio.Queue):
    progress = ProgressReporter(queue)
    session = get_session()
    try:
        analyzer = ReconAnalyzer(url, progress)
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

    for section in ["endpoints", "secrets", "jwts", "cookies", "pii",
                    "env_vars", "external_domains", "api_docs", "js_files"]:
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
        for section in ["endpoints", "secrets", "jwts", "cookies", "pii", "env_vars", "external_domains"]:
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
    lines.append("## Resumo Estatístico")
    for k, v in report.get("stats", {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("\n## Tecnologias Detectadas")
    for t in report.get("technologies", []):
        lines.append(f"- {t}")
    lines.append("\n## Endpoints Descobertos")
    for e in report.get("endpoints", []):
        lines.append(f"- `{'/'.join(e['methods'])}` {e['path']} (módulo: {e['module']})")
    lines.append("\n## Secrets Identificados")
    for s in report.get("secrets", []):
        lines.append(f"- {s['type']}: `{s['match_preview']}` (fonte: {s['source_file']})")
    lines.append("\n## JWTs")
    for j in report.get("jwts", []):
        lines.append(f"- {j['token_preview']} — alg: {j['header'].get('alg')}, "
                      f"exp: {j['payload'].get('exp')}")
    lines.append("\n## Cookies")
    for c in report.get("cookies", []):
        lines.append(f"- {c['name']} (HttpOnly={c['http_only']}, Secure={c['secure']}, "
                      f"SameSite={c['same_site']})")
    lines.append("\n## PII Identificada")
    for p in report.get("pii", []):
        lines.append(f"- {p['type']}: {p['value']}")
    lines.append("\n## Domínios Externos")
    for d in report.get("external_domains", []):
        lines.append(f"- {d}")
    lines.append("\n## Swagger/OpenAPI")
    for a in report.get("api_docs", []):
        lines.append(f"- {a['url']} (status {a['status_code']})")
    return "\n".join(lines)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
