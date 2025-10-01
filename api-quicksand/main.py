# main.py

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
import requests
import mimetypes
import uvicorn # <-- ¡Necesitas importar Uvicorn!

app = FastAPI(
    title="File Proxy API",
    description="API para resolver problemas de CORS y devolver archivos desde una URL de origen.",
    version="1.0.0"
)

# ... (Tu configuración de CORS y tus funciones proxy_file, read_root permanecen igual) ...

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


@app.get("/api/proxy-file")
async def proxy_file(source_url: str):
    # ... (Lógica de tu proxy) ...
    if not source_url:
        raise HTTPException(status_code=400, detail="El parámetro 'source_url' es obligatorio.")
    
    try:
        response = requests.get(source_url, stream=True)
        response.raise_for_status()

        content_type, _ = mimetypes.guess_type(source_url)
        if not content_type:
             content_type = response.headers.get('Content-Type') or "application/octet-stream"

        filename = source_url.split('/')[-1]

        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename=\"{filename}\"",
                "Content-Length": str(len(response.content)),
            }
        )

    except requests.exceptions.HTTPError as e:
        return HTTPException(
            status_code=e.response.status_code, 
            detail=f"Error al obtener el archivo de la URL de origen: {e.response.reason}"
        )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error de conexión al URL de origen: {str(e)}"
        )


@app.get("/")
def read_root():
    return {"message": "File Proxy API está funcionando. Usa /api/proxy-file?source_url=..."}


# ----------------------------------------------------------------------
# INICIO DEL SERVIDOR ESPECIFICANDO EL PUERTO DENTRO DEL CÓDIGO
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # La función run() arranca el servidor Uvicorn
    # y le especifica el host (127.0.0.1) y el puerto (8001)
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8001, 
        reload=True  # Puedes quitar esto en producción
    )
#python3 main.py