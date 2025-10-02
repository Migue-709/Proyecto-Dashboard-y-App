# main.py

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
import requests
import mimetypes
import uvicorn
import pprint  # Necesitas pprint para imprimir los resultados

# Importar la librería quicksand
try:
    from quicksand.quicksand import quicksand
except ImportError:
    print(
        "ADVERTENCIA: La librería 'quicksand' no está instalada. Ejecuta: pip install quicksand"
    )

    # Define una clase mock para que el código no falle si no está instalada
    class QuickSandMock:
        def __init__(self, *args, **kwargs):
            self.results = {"error": "Librería quicksand no instalada en el servidor."}

        def process(self):
            pass

    quicksand = QuickSandMock
# ----------------------------------------------------------------------

app = FastAPI(
    title="File Proxy & Malware Analysis API",
    description="API para el análisis de archivso y documentos Con QuickSand.",
    version="1.0.0",
)

origins = [
    "*",
    # "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Utilizamos 'File' y 'UploadFile' para recibir el archivo del frontend.


@app.post("/api/quicksand-analyze")
async def quicksand_analyze_file(file: UploadFile = File(...)):
    """
    Recibe un archivo subido (desde un input[type="file"]) y lo analiza
    directamente con la librería QuickSand.
    """
    print(f"Recibido archivo: {file.filename}, tipo: {file.content_type}")

    # El archivo subido viene como un objeto 'UploadFile'.
    # 1. Leemos el contenido binario del archivo subido.
    #    .read() es un método asíncrono.
    try:
        datos_binarios = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error al leer el archivo: {str(e)}"
        )
    finally:
        # Aseguramos que el stream se cierre después de leer
        await file.close()

    # Si no hay datos (archivo vacío), devolvemos un error.
    if not datos_binarios:
        raise HTTPException(
            status_code=400, detail="El archivo está vacío o no se proporcionó."
        )

    # 2. Pasamos los datos binarios directamente al constructor de quicksand.
    #    Esto es la clave: QuickSand procesa el contenido de la memoria.
    try:
        # Puedes añadir parámetros como timeout, strings=True, etc.
        qs = quicksand(datos_binarios)
        qs.process()

        raw = getattr(qs, "results", {}) or {}

        # Estructura esperada por el frontend:
        # analysis_results: { risk: str, score: int, tags: list[str], results: {flow: [detections]|object} }
        # QuickSand en algunas versiones devuelve ya algo similar; si no, construimos.

        # Si ya existe la clave 'results' asumimos que el formato es moderno y solo enriquecemos.
        if isinstance(raw, dict) and "results" in raw:
            per_flow = raw.get("results") or {}
            # Agregamos score/tags globales si faltan
            all_detections = []
            for v in per_flow.values():
                if isinstance(v, list):
                    all_detections.extend(v)
            agg_score = (
                raw.get("score")
                if raw.get("score") is not None
                else len(all_detections)
            )
            agg_tags = (
                raw.get("tags")
                if raw.get("tags") is not None
                else list(
                    {
                        d.get("rule") or d.get("tag")
                        for d in all_detections
                        if isinstance(d, dict) and (d.get("rule") or d.get("tag"))
                    }
                )
            )
            # Derivar riesgo si falta
            risk = raw.get("risk") or raw.get("state")
            if not risk:
                if agg_score >= 6:
                    risk = "high"
                elif agg_score >= 3:
                    risk = "medium"
                elif agg_score >= 1:
                    risk = "low"
                else:
                    risk = "none"
            normalized = {
                "risk": risk,
                "score": agg_score,
                "tags": agg_tags,
                "results": per_flow,
            }
        else:
            # Formato alternativo: raw es directamente el mapping per_flow
            per_flow = raw if isinstance(raw, dict) else {}
            all_detections = []
            for v in per_flow.values():
                if isinstance(v, list):
                    all_detections.extend(v)
            agg_score = len(all_detections)
            agg_tags = list(
                {
                    d.get("rule") or d.get("tag")
                    for d in all_detections
                    if isinstance(d, dict) and (d.get("rule") or d.get("tag"))
                }
            )
            # Heurística de riesgo
            if agg_score >= 6:
                risk = "high"
            elif agg_score >= 3:
                risk = "medium"
            elif agg_score >= 1:
                risk = "low"
            else:
                risk = "none"
            normalized = {
                "risk": risk,
                "score": agg_score,
                "tags": agg_tags,
                "results": per_flow,
            }

        return {
            "status": "análisis completado",
            "filename": file.filename,
            "content_type": file.content_type,
            "file_size": len(datos_binarios),
            "analysis_results": normalized,
        }

    except Exception as e:
        # Capturamos cualquier error que ocurra durante el análisis de QuickSand
        raise HTTPException(
            status_code=500,
            detail=f"Error interno durante el análisis con QuickSand: {str(e)}",
        )


# ----------------------------------------------------------------------
# (Tu función read_root y la ejecución de Uvicorn permanecen igual)
# ----------------------------------------------------------------------


@app.get("/")
def read_root():
    return {
        "message": "File Proxy API está funcionando. Usa /api/proxy-file?source_url=... o haz POST a /api/quicksand-analyze con un archivo."
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
