# main.py

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
import requests
import mimetypes
import uvicorn
import pprint # Necesitas pprint para imprimir los resultados

# Importar la librería quicksand
try:
    from quicksand.quicksand import quicksand
except ImportError:
    print("ADVERTENCIA: La librería 'quicksand' no está instalada. Ejecuta: pip install quicksand")
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
    version="1.0.0"
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
        raise HTTPException(status_code=500, detail=f"Error al leer el archivo: {str(e)}")
    finally:
        # Aseguramos que el stream se cierre después de leer
        await file.close()

    # Si no hay datos (archivo vacío), devolvemos un error.
    if not datos_binarios:
        raise HTTPException(status_code=400, detail="El archivo está vacío o no se proporcionó.")

    # 2. Pasamos los datos binarios directamente al constructor de quicksand.
    #    Esto es la clave: QuickSand procesa el contenido de la memoria.
    try:
        # Puedes añadir parámetros como timeout, strings=True, etc.
        qs = quicksand(datos_binarios) 
        qs.process()
        
        # 3. Retornamos los resultados del análisis
        #    La función pprint.pformat formatea el diccionario de resultados a una string bonita.
        #    (FastAPI serializará el diccionario de resultados directamente a JSON por defecto,
        #     pero si QuickSand retorna un objeto complejo, es mejor devolver el dict completo).
        return {
            "status": "análisis completado",
            "filename": file.filename,
            "content_type": file.content_type,
            "file_size": len(datos_binarios),
            "analysis_results": qs.results
        }
        
    except Exception as e:
        # Capturamos cualquier error que ocurra durante el análisis de QuickSand
        raise HTTPException(
            status_code=500, 
            detail=f"Error interno durante el análisis con QuickSand: {str(e)}"
        )

# ----------------------------------------------------------------------
# (Tu función read_root y la ejecución de Uvicorn permanecen igual)
# ----------------------------------------------------------------------

@app.get("/")
def read_root():
    return {"message": "File Proxy API está funcionando. Usa /api/proxy-file?source_url=... o haz POST a /api/quicksand-analyze con un archivo."}


if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8001, 
        reload=True
    )