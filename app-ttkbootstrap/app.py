import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog
import os 
import hashlib
import requests
import pefile
from scanner import run_full_analysis
import threading
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
    status_callback("Consultando VirusTotal...")
    if VT_API_KEY == "TU_API_KEY_DE_VIRUSTOTAL_AQUI":
        return {"error": "API Key de VirusTotal no configurada."}
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
                        {
                            "vendor": vendor,
                            "result": result.get("result", ""),
                            "engine_name": result.get("engine_name", vendor),
                        }
                    )
            return {
                "malicious_detections": stats.get("malicious", 0),
                "total_scans": sum(stats.values()),
                "names": data.get("names", []),
                "meaningful_name": data.get("meaningful_name"),
                "type_tag": data.get("type_tag"),
                "signature_info": data.get("signature_info"),
                "times_submitted": data.get("times_submitted"),
                "popular_threat_classification": data.get(
                    "popular_threat_classification"
                ),
                "trid": data.get("trid"),
                "exiftool": data.get("exiftool"),
                "tags": data.get("tags"),
                "malicious_vendors": malicious_vendors,
            }
        elif response.status_code == 404:
            return {"error": "Hash no encontrado en VirusTotal."}
        else:
            return {"error": f"Error en API (Código: {response.status_code})"}
    except Exception as e:
        return {"error": f"No se pudo conectar a VirusTotal: {e}"}


def analizar_pe(filepath, status_callback):
    status_callback("Analizando imports del ejecutable...")
    num_imports, file_version = 0, "N/A"
    try:
        pe = pefile.PE(filepath)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                num_imports += len(entry.imports)
        if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "VS_FIXEDFILEINFO"):
            for fileinfo in pe.VS_VERSIONINFO:
                if fileinfo.Key == b"VS_FIXEDFILEINFO":
                    ver_info = pe.VS_FIXEDFILEINFO[0]
                    file_version = f"{ver_info.FileVersionMS >> 16}.{ver_info.FileVersionMS & 0xFFFF}.{ver_info.FileVersionLS >> 16}.{ver_info.FileVersionLS & 0xFFFF}"
                    break
    except pefile.PEFormatError:
        return {"type": "Desconocido", "num_imports": 0, "file_version": "N/A"}
    except Exception:
        return {"type": "Error", "num_imports": 0, "file_version": "N/A"}
    return {
        "type": "Archivo PE de Windows (exe/dll)",
        "num_imports": num_imports,
        "file_version": file_version,
    }


def generar_veredicto(vt_results):
    detections = vt_results.get("malicious_detections", 0)
    if detections > 5:
        return {
            "texto": "🔴 POTENCIALMENTE PELIGROSO",
            "color": "red",
            "riesgo": "Alto",
        }
    elif 1 < detections <= 5:
        return {
            "texto": "🔴 POTENCIALMENTE PELIGROSO",
            "color": "red",
            "riesgo": "Medio-Alto",
        }
    elif detections > 0:
        return {
            "texto": "🟠 POTENCIAL FALSO POSITIVO",
            "color": "orange",
            "riesgo": "Bajo",
        }
    else:
        return {
            "texto": "🟢 PROBABLEMENTE SEGURO",
            "color": "green",
            "riesgo": "Muy Bajo",
        }


def format_file_report(data):
    summary = data.get("analysis_summary", {})
    verdict = summary.get("risk_verdict", {})
    report = [
        f"--- VEREDICTO: {verdict.get('texto', 'N/A')} ---",
        "\n--- RESUMEN DEL ANÁLISIS ---",
        f"Score (Detecciones VT): {summary.get('score', 'N/A')}",
        f"Warnings (Imports sospechosos): {summary.get('warnings', 'N/A')}",
        "\n--- INFORMACIÓN DEL ARCHIVO ---",
        f"Filename: {data.get('filename', 'N/A')}",
        f"Size: {data.get('size_bytes', 0)} bytes ({data.get('size_kb', 0.0):.2f} KB)",
        f"Type: {data.get('type', 'N/A')}",
        f"Header (primeros 32 bytes): {data.get('header', 'N/A')}",
        f"Nombre representativo: {data.get('meaningful_name', 'N/A')}",
        f"Tipo de archivo (type_tag): {data.get('type_tag', 'N/A')}",
        f"Firma digital: {data.get('signature_info', 'N/A')}",
        f"Veces enviado a VT: {data.get('times_submitted', 'N/A')}",
    ]
    ptc = data.get("popular_threat_classification", {})
    threat = (
        ptc.get("suggested_threat_label", "N/A")
        if ptc and isinstance(ptc, dict)
        else "N/A"
    )
    report.extend(
        [
            f"Clasificación de amenaza: {threat}",
            f"TRiD: {data.get('trid', 'N/A')}",
            f"ExifTool: {data.get('exiftool', 'N/A')}",
            f"Etiquetas: {', '.join(data.get('tags', [])) if data.get('tags') else 'N/A'}",
            "\n--- HASHES ---",
            f"MD5:    {data.get('md5', 'N/A')}",
            f"SHA1:   {data.get('sha1', 'N/A')}",
            f"SHA256: {data.get('sha256', 'N/A')}",
            f"SHA512: {data.get('sha512', 'N/A')}",
        ]
    )
    malicious_vendors = data.get("malicious_vendors", [])
    if malicious_vendors:
        report.append("\n--- DETECCIONES DE PROVEEDORES ---")
        for v in malicious_vendors:
            report.append(f"- {v.get('vendor', 'N/A')}: {v.get('result', 'N/A')}")
    timing = data.get("timing", {})
    report.extend(
        [
            "\n--- METADATOS DEL ANÁLISIS ---",
            f"Versión del Script: {data.get('version', 'N/A')}",
            f"Análisis iniciado: {time.ctime(timing.get('started', 0))}",
            f"Análisis finalizado: {time.ctime(timing.get('finished', 0))}",
            f"Tiempo transcurrido: {timing.get('elapsed', 0.0):.4f} segundos",
        ]
    )
    return "\n".join(report)


def resource_path(relative_path):
    base_path = getattr(
        sys,
        "_MEIPASS",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "icons")),
    )
    return os.path.join(base_path, relative_path)

class MalwareScanApp(ttk.Window):
    def __init__(self, themename="superhero",):
        super().__init__(themename=themename)
        self.title("MalwareScan - Dashboard de Análisis")
        self.geometry("1000x700") 
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.views = {} 
        self.current_view = None

        # Usaremos esta variable para guardar la ruta seleccionada
        self.selected_file_path = tk.StringVar() 
        self.selected_file_path.set("No se seleccionó ningún archivo")

        self.malware_icon = self.create_icon_placeholder("😈", 24)
        self.moon_icon = self.create_icon_placeholder("🌙", 20)
        self.file_icon = self.create_icon_placeholder("📄", 50)
        self.user_icon = self.create_icon_placeholder("👋", 16)
        
        self.sidebar = ttk.Frame(self, width=200, padding="15 10 15 10", bootstyle="primary")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.create_sidebar_widgets()

        self.view_container = ttk.Frame(self, padding=20)
        self.view_container.grid(row=0, column=1, sticky="nsew")
        self.view_container.grid_rowconfigure(0, weight=1)
        self.view_container.grid_columnconfigure(0, weight=1)

        self.create_views(self.view_container)
        
        self.show_view("Escanear Archivo")


    def create_icon_placeholder(self, text, size):
        """Crea un placeholder de ícono usando una etiqueta para simplicidad."""
        return text

    # ===============================================
    # 1. SIDEBAR
    # ===============================================
    def create_sidebar_widgets(self):
        """Crea los widgets dentro de la barra lateral."""
        
        title_frame = ttk.Frame(self.sidebar, bootstyle="primary")
        title_frame.pack(fill=X, pady=(0, 30))
        
        ttk.Label(title_frame, text=self.malware_icon, font=('Arial', 24), bootstyle="inverse-primary").pack(side=LEFT)
        ttk.Label(title_frame, text="MalwareScan", font=('Helvetica', 14, 'bold'), bootstyle="inverse-primary").pack(side=LEFT, padx=5, pady=10)

        self.nav_buttons = {}
        for text in ["Escanear Archivo", "Extractor de String", "Historial"]:
            style = "primary-link" if text == "Escanear Archivo" else "secondary-link"
            btn = ttk.Button(self.sidebar, text=text, bootstyle=style, 
                             command=lambda t=text: self.show_view(t))
            btn.pack(fill=X, pady=5)
            self.nav_buttons[text] = btn
        
        ttk.Separator(self.sidebar, orient=HORIZONTAL).pack(fill=X, pady=30)
        
        footer_spacer = ttk.Frame(self.sidebar, bootstyle="primary")
        footer_spacer.pack(fill=BOTH, expand=True)

        ttk.Label(self.sidebar, text=f"{self.user_icon} Hi, herrera.joses 👋", bootstyle="inverse-primary").pack(pady=(10, 5), anchor=W)
        
        info_frame = ttk.Frame(self.sidebar, bootstyle="info", padding=10)
        info_frame.pack(fill=X, pady=10)
        
        ttk.Label(info_frame, text="Detector de virus", font=('Helvetica', 10, 'bold'), bootstyle="inverse-info").pack(fill=X)
        info_text = "Analiza archivos de todo tipo: PDF, Word, Excel, ZIP, RAR, y muchos más. ¡Sube tu documento y protégelo!"
        ttk.Label(info_frame, text=info_text, wraplength=170, bootstyle="inverse-info").pack(fill=X)

    # ===============================================
    # 2. VISTAS DINÁMICAS (FRAMES)
    # ===============================================
    def create_views(self, container):
        """Crea y registra todos los frames de vista."""
        
        self.views["Escanear Archivo"] = self.create_scan_view(container)
        self.views["Extractor de String"] = self.create_string_view(container)
        self.views["Historial"] = self.create_history_view(container)
    def a():
        print("AAAAAA")
    def show_view(self, view_name):
        """Muestra el frame de la vista seleccionada y oculta las demás."""
        
        if self.current_view:
            self.current_view.grid_forget()
            
        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.config(bootstyle="primary-link")
            else:
                btn.config(bootstyle="secondary-link")

        view = self.views[view_name]
        view.grid(row=0, column=0, sticky="nsew")
        self.current_view = view


    # --- DEFINICIÓN DE VISTAS ESPECÍFICAS ---

    def create_scan_view(self, container):
        """Crea la vista para Escanear Archivo con el botón centrado."""
        scan_view = ttk.Frame(container)
        scan_view.grid_columnconfigure(0, weight=1)
        scan_view.grid_rowconfigure(5, weight=1) 
        
        # Fila superior
        header_frame = ttk.Frame(scan_view)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(header_frame, text="Dashboard de Análisis", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, sticky=W)
        
        self.theme_btn = ttk.Button(header_frame, text=self.moon_icon, command=self.toggle_theme, bootstyle="secondary")
        self.theme_btn.grid(row=0, column=1, sticky=E)
        
        ttk.Label(scan_view, text="Escanea tu archivo ahora", font=('Helvetica', 14, 'bold')).grid(row=1, column=0, sticky=W, pady=(20, 5))
        
        # --- ZONA DE BOTÓN CENTRADO (MODIFICADA) ---
        file_input_frame = ttk.Frame(scan_view, padding=0)
        file_input_frame.grid(row=2, column=0, sticky="ew", pady=(10, 50)) 
        
        # Eliminamos file_input_frame.grid_columnconfigure(0, weight=1) para permitir el centrado

        # Etiqueta que muestra la ruta (opcional, pero útil)
        ttk.Label(
            file_input_frame, 
            textvariable=self.selected_file_path, 
            font=('Helvetica', 10),
            bootstyle="secondary",
            anchor=CENTER # Centra el texto dentro de la etiqueta
        ).grid(row=0, column=0, sticky="ew", columnspan=1, pady=(0, 10))
        file_input_frame.grid_columnconfigure(0, weight=1) # Asegura que la etiqueta tome el espacio

        # 2. Botón de Carpeta (Folder Button) - Centrado
        folder_btn = ttk.Button(
            file_input_frame, 
            text="📁 Seleccionar Archivo", 
            command=self.open_file_dialog, 
            bootstyle="secondary", 
            width=20 # Darle un ancho fijo para que se vea centrado
        )
        # Usamos row=1, column=0, y sticky="" (vacío) para centrar en la celda
        folder_btn.grid(row=1, column=0, sticky="", ipady=10) 

        # 3. Botón ANALIZAR
        analyze_btn = ttk.Button(
            scan_view, 
            text="ANALIZAR >", 
            bootstyle="primary-outline", 
            padding=(40, 15), 
            command=self.start_full_scan
        )
        # sticky="" centra el botón ANALIZAR en su fila
        analyze_btn.grid(row=3, column=0, sticky="", pady=(20, 30)) 
        
        ttk.Label(scan_view, text="Resultados del Análisis", font=('Helvetica', 14, 'bold')).grid(row=4, column=0, sticky=W, pady=(30, 5))

        results_zone = ttk.Frame(scan_view, bootstyle="dark", padding=30, relief=RIDGE)
        results_zone.grid(row=5, column=0, sticky="nsew")
        results_zone.grid_columnconfigure(0, weight=1)
        results_zone.grid_rowconfigure(0, weight=1)
        
        ttk.Label(results_zone, text="Aquí se mostrarán los resultados de su análisis.", 
                  bootstyle="secondary", anchor=CENTER).grid(row=0, column=0, sticky="") 

        return scan_view

    def create_string_view(self, container):
        """Crea la vista para Extractor de String."""
        string_view = ttk.Frame(container)
        string_view.grid_columnconfigure(0, weight=1)
        string_view.grid_rowconfigure(2, weight=2)
        string_view.grid_rowconfigure(5, weight=1)

        ttk.Label(string_view, text="Extractor de Strings Avanzado", font=('Helvetica', 18, 'bold'), bootstyle="primary").grid(row=0, column=0, pady=20, sticky=W)
        
        ttk.Label(string_view, text="Pega el binario o texto para extraer strings:", bootstyle="secondary").grid(row=1, column=0, sticky=W, pady=(10, 5))
        text_input = tk.Text(string_view, height=15, width=80, bg='#212121', fg='white', insertbackground='white')
        text_input.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        
        ttk.Button(string_view, text="Extraer Strings", bootstyle="success").grid(row=3, column=0, sticky=W, pady=15)
        
        ttk.Label(string_view, text="Strings Encontrados:", bootstyle="secondary").grid(row=4, column=0, sticky=W, pady=(10, 5))
        results_box = ttk.Text(string_view, height=10, width=80, bg='#212121', fg='#00ff00', insertbackground='white')
        results_box.insert(END, "Aquí aparecerán las cadenas de texto extraídas.")
        results_box.grid(row=5, column=0, sticky="ew", padx=10, pady=5)
        
        return string_view

    def create_history_view(self, container):
        """Crea la vista para Historial."""
        history_view = ttk.Frame(container)
        history_view.grid_columnconfigure(0, weight=1)
        history_view.grid_rowconfigure(1, weight=1)

        ttk.Label(history_view, text="Historial de Análisis Recientes", font=('Helvetica', 18, 'bold'), bootstyle="primary").grid(row=0, column=0, pady=20, sticky=W)
        
        columns = ("#1", "#2", "#3")
        history_table = ttk.Treeview(history_view, columns=columns, show='headings', bootstyle="info")
        history_table.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        history_table.heading("#1", text="Fecha")
        history_table.heading("#2", text="Nombre del Archivo")
        history_table.heading("#3", text="Resultado")

        history_table.column("#1", width=150, anchor=CENTER)
        history_table.column("#2", width=350)
        history_table.column("#3", width=100, anchor=CENTER)

        history_table.insert('', END, values=('2025-09-27', 'virus_sample.exe', 'Malicioso'))
        history_table.insert('', END, values=('2025-09-26', 'update.zip', 'Limpio'))
        history_table.insert('', END, values=('2025-09-25', 'doc_finanzas.pdf', 'Limpio'))

        vscrollbar = ttk.Scrollbar(history_view, orient=VERTICAL, command=history_table.yview)
        history_table.configure(yscrollcommand=vscrollbar.set)
        vscrollbar.grid(row=1, column=1, sticky="ns")

        return history_view

    # -----------------------------------------------
    # --- FUNCIONES GENERALES (Lógica Corregida con after) ---
    # -----------------------------------------------
    def execute_scanner(self, filepath):
        print('EXECUTE SCANNER')
        """Función que corre en un hilo separado para llamar a scanner.py."""
        try:
            # Llama a la función principal en scanner.py, pasándole la función de callback
            results = scanner.run_full_analysis(filepath, self.update_status)

            # Formatear el reporte de texto usando el método de scanner
            final_report = scanner.format_file_report(results)
            
            # Devolver el control a la GUI para mostrar los resultados y habilitar botones
            self.show_final_report(final_report, enable_buttons=True)

        except Exception as e:
            error_report = f"Error Crítico durante el análisis: {e}"
            self.show_final_report(error_report, enable_buttons=True)
    def start_full_scan(self):
        """Verifica la ruta e inicia la ejecución asíncrona del escáner."""
        filepath = self.selected_file_path.get()
        # ... (validaciones) ...

        # Deshabilitar botones para evitar múltiples clics
        # ¡Esto ahora funciona porque self.analyze_btn existe!
        self.analyze_btn.config(state=tk.DISABLED) 
        
        # También debes deshabilitar el botón de la carpeta
        self.folder_btn.config(state=tk.DISABLED)
        
        self.update_status("Iniciando análisis...")
        
        # Iniciar el proceso en un hilo secundario
        thread = threading.Thread(target=self.execute_scanner, args=(filepath,))
        thread.start()
    

    def _execute_file_dialog(self, temp_root):
        """
        Ejecuta el diálogo de archivo real.
        Se llama *después* de un pequeño retraso.
        """
        file_path = None 
        try:
            file_path = filedialog.askopenfilename(
                parent=temp_root, 
                title="Selecciona un archivo para escanear",
                filetypes=(
                    ("Archivos Soportados", "*.exe;*.dll;*.zip;*.rar;*.7z;*.pdf;*.doc;*.docx;*.xls;*.xlsx"),
                    ("Todos los archivos", "*.*"),
                )
            )

            # Procesa el resultado
            if file_path:
                self.selected_file_path.set(file_path)
            else:
                if self.selected_file_path.get() == "No se seleccionó ningún archivo" or not self.selected_file_path.get():
                     self.selected_file_path.set("No se seleccionó ningún archivo")

        except Exception as e:
            print(f"Error al abrir el diálogo de archivo: {e}")
        
        finally:
            # Limpieza final
            temp_root.destroy()
            self.update_idletasks()


    def open_file_dialog(self):
        """
        Inicia el proceso de apertura de archivo usando un hack de aislamiento y temporización.
        """
        # 1. Crea la instancia temporal de Tk y la oculta (Aislamiento clave)
        self.file_path = filedialog.askopenfilename(
            title="Seleccionar archivo para análisis",
            filetypes=(
                ("Archivos Soportados", "*.exe *.dll *.zip *.rar *.7z"),
                ("Todos los archivos", "*.*"),
            ),
        )
        if self.file_path:
            self.selected_file_path.set(self.file_path)
        else:
            self.selected_file_path.set("No se seleccionó ningún archivo")




    def toggle_theme(self):
        """Alterna entre temas claros y oscuros de ttkbootstrap."""
        current_theme = self.style.theme.name
        if 'dark' in current_theme or 'superhero' in current_theme or 'cyborg' in current_theme:
            self.style.theme_use('flatly')
            self.theme_btn.config(text="🌞")
        else:
            self.style.theme_use('superhero')
            self.theme_btn.config(text="🌙")


if __name__ == "__main__":
    app = MalwareScanApp()
    app.mainloop()