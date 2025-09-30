# ==========================================================
# ARCHIVO: scanner.py
# Contiene la lógica de análisis, separada de la interfaz.
# ==========================================================
import hashlib
import requests
import pefile
import time
import os
import json
from quicksand.quicksand import quicksand

# Clave de VirusTotal (¡Reemplaza con la tuya para usar!)
VT_API_KEY = "0b3ec7bc013f9a13f623c7d027ffbd543d13f7e540b71121a9109597b3c52caa"
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
SCRIPT_VERSION = "3.0"


def calcular_hashes(filepath):
    """Calcula MD5, SHA1, SHA256 y SHA512 de un archivo."""
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                for h in hashes.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hashes.items()}
    except Exception:
        return None


def consultar_virustotal(sha256, status_callback):
    """Consulta el hash SHA256 en la API de VirusTotal."""
    status_callback("Consultando VirusTotal...")
    if VT_API_KEY == "0b3ec7bc013f9a13f623c7d027ffbd543d13f7e540b71121a9109597b3c52caa" or len(VT_API_KEY) < 60:
        return {"error": "API Key de VirusTotal no configurada o es la clave por defecto."}
        
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(VT_API_URL + sha256, headers=headers, timeout=20)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_vendors = []
            last_analysis_results = data.get("last_analysis_results", {})
            
            for vendor, result in last_analysis_results.items():
                if result.get("category") == "malicious":
                    malicious_vendors.append(
                        {"vendor": vendor, "result": result.get("result", "")}
                    )
            
            return {
                "malicious_detections": stats.get("malicious", 0),
                "total_scans": sum(stats.values()),
                "malicious_vendors": malicious_vendors,
                # Se pueden añadir más campos de VT aquí si es necesario
            }
        elif response.status_code == 404:
            return {"error": "Hash no encontrado en VirusTotal (No escaneado antes)."}
        else:
            return {"error": f"Error en API (Código: {response.status_code})"}
    except Exception as e:
        return {"error": f"No se pudo conectar a VirusTotal: {e}"}


def analizar_pe(filepath, status_callback):
    """Analiza la estructura PE (para ejecutables de Windows)."""
    status_callback("Analizando imports del ejecutable...")
    num_imports, file_version = 0, "N/A"
    try:
        pe = pefile.PE(filepath)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                num_imports += len(entry.imports)
        
        if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "VS_FIXEDFILEINFO"):
            # Lógica para extraer la versión
            ver_info = pe.VS_FIXEDFILEINFO[0]
            file_version = f"{pe.VS_FIXEDFILEINFO[0].FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO[0].FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO[0].FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO[0].FileVersionLS & 0xFFFF}"
        
        file_type = "Archivo PE (exe/dll)"
        
    except pefile.PEFormatError:
        file_type = "Archivo Binario/Documento (No PE)"
        
    except Exception:
        file_type = "Error de Análisis Estático"
        
    return {
        "type": file_type,
        "num_imports": num_imports,
        "file_version": file_version,
    }


def generar_veredicto(vt_results):
    """Genera un veredicto de riesgo basado en las detecciones de VT."""
    detections = vt_results.get("malicious_detections", 0)
    if detections > 5:
        return {"texto": "🔴 ALTO RIESGO", "color": "danger", "riesgo": "Alto"}
    elif 1 < detections <= 5:
        return {"texto": "🟠 RIESGO MEDIO", "color": "warning", "riesgo": "Medio"}
    elif detections > 0:
        return {"texto": "🟡 BAJO RIESGO / FALSO POSITIVO", "color": "warning", "riesgo": "Bajo"}
    else:
        return {"texto": "🟢 PROBABLEMENTE SEGURO", "color": "success", "riesgo": "Muy Bajo"}


def format_file_report(data):
    """Formatea el diccionario de resultados en un reporte de texto legible."""
    summary = data.get("analysis_summary", {})
    verdict = summary.get("risk_verdict", {})
    
    size_bytes = data.get('size_bytes', 0)
    size_kb = size_bytes / 1024 if size_bytes else 0.0
    header_raw = data.get('header', b'').hex() if isinstance(data.get('header'), bytes) else str(data.get('header'))

    report = [
        f"--- VEREDICTO DE RIESGO: {verdict.get('texto', 'N/A')} ({verdict.get('riesgo', 'N/A')}) ---",
        "\n--- RESUMEN ---",
        f"Detecciones en VirusTotal: {summary.get('score', 'N/A')}/{data.get('total_scans', 'N/A')}",
        f"Tiempo de análisis: {data.get('timing', {}).get('elapsed', 0.0):.2f} segundos",
        
        "\n--- INFORMACIÓN DEL ARCHIVO ---",
        f"Filename: {data.get('filename', 'N/A')}",
        f"Size: {size_bytes} bytes ({size_kb:.2f} KB)",
        f"Type: {data.get('type', 'N/A')}",
        f"Versión del Archivo (PE): {data.get('file_version', 'N/A')}",
        f"Imports PE detectados: {data.get('num_imports', 'N/A')}",
        
        "\n--- HASHES ---",
        f"MD5:    {data.get('md5', 'N/A')}",
        f"SHA256: {data.get('sha256', 'N/A')}",
    ]
    
    malicious_vendors = data.get("malicious_vendors", [])
    if malicious_vendors:
        report.append("\n--- DETECCIONES DE PROVEEDORES ---")
        for v in malicious_vendors:
            report.append(f"- {v.get('vendor', 'N/A')}: Malicioso ({v.get('result', 'N/A')})")
    else:
         report.append("\n--- DETECCIONES DE PROVEEDORES ---\n- Ninguna detección maliciosa registrada.")
         
    return "\n".join(report)


def run_full_analysis(filepath, status_callback):
    """
    Función principal que ejecuta todo el flujo de análisis.
    Se llama desde el hilo en main_app.py.
    """
    print('RUN FULL ANALYSIS')
    start_time = time.time()
    results = {"filename": os.path.basename(filepath), "version": SCRIPT_VERSION, "timing": {"started": start_time}}

    try:
        # 1. Hashes y Metadata
        status_callback("Calculando hashes...")
        file_hashes = calcular_hashes(filepath)
        if file_hashes is None:
            raise Exception("Error al calcular hashes o abrir el archivo.")

        results.update(file_hashes)
        results["size_bytes"] = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            results["header"] = f.read(32)

        sha256 = file_hashes.get("sha256")
        
        # 2. Análisis PE/Estático
        pe_results = analizar_pe(filepath, status_callback)
        results.update(pe_results)

        # 3. Consulta a VirusTotal
        vt_results = consultar_virustotal(sha256, status_callback)
        
        if "error" in vt_results:
            results["analysis_summary"] = {"risk_verdict": {"texto": f"Error VT: {vt_results['error']}", "color": "danger", "riesgo": "N/A"}, "score": 0}
            status_callback(f"Análisis con error: {vt_results['error']}")
        else:
            results.update(vt_results)
            verdict = generar_veredicto(vt_results)
            results["analysis_summary"] = {"risk_verdict": verdict, "score": results.get("malicious_detections", 0)}
            status_callback(f"Análisis Completo. Resultado: {verdict['texto']}")

    except Exception as e:
        status_callback(f"Fallo del análisis: {e}")
        results["analysis_summary"] = {"risk_verdict": {"texto": "ERROR INTERNO", "color": "danger", "riesgo": "Alto"}, "score": 0}

    finally:
        end_time = time.time()
        results["timing"]["finished"] = end_time
        results["timing"]["elapsed"] = end_time - start_time
        return results