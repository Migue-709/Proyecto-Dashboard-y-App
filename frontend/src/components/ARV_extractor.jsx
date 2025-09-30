import { useState } from 'react';
// Helpers para búsquedas seguras y eficientes
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
}
// Objeto que mapea nombres de herramientas a sus componentes
const componentMap = {
  'Extractor de Strings': StringExtractor,
  'From Hex': FromHexConverter,
  'To Hex': ToHexConverter,
  'Hexdump': HexdumpViewer,
  'Regular Expressions': RegexExtractor,
};

// Lista de herramientas (las llaves del objeto de mapeo)
const tools = Object.keys(componentMap);

function ToolSelector({ file }) {
  const [selectedTool, setSelectedTool] = useState(null);

  // Obtiene el componente seleccionado del mapa
  const SelectedComponent = componentMap[selectedTool];

  return (
    <div className="flex flex-col md:flex-row h-screen bg-white dark:bg-slate-950  rounded-xl shadow-sm p-8 md:max-h-[300px] lg:max-h-[400px]">
      {/* Menú de navegación lateral */}
      <ul className='flex flex-row md:flex-col gap-2 items-start p-4 bg-white dark:bg-slate-950 border-b md:border-r border-gray-300 dark:border-slate-700 overflow-x-auto'>
        {tools.map((toolName, index) => (
          <li
            onClick={() => setSelectedTool(toolName)}
            // En móvil, agregamos 'flex-shrink-0' para evitar que se compriman 
            // y 'whitespace-nowrap' para mantenerlos en una sola línea (lo cual activa el scroll).
            className={`p-2 rounded-md cursor-pointer mb-2 flex-shrink-0 whitespace-nowrap
          ${selectedTool === toolName
                ? 'bg-blue-500 text-white'
                : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-800 dark:text-gray-200'}
          // En escritorio, restauramos el ancho completo
          md:w-full
        `}
            key={index}
          >
            {toolName}
          </li>
        ))}
      </ul>

      {/* Área de visualización de los componentes */}
      <div className='flex-1 p-8 overflow-y-auto'>
        {!selectedTool && (
          <div className='grid place-content-center size-full text-gray-500 dark:text-gray-400'>
            <span>Aquí se mostrarán tus resultados. Selecciona una herramienta.</span>
          </div>
        )}

        {SelectedComponent && <SelectedComponent file={file} />}
      </div>
    </div>
  );
}
function StringExtractor({ file }) {
  const [extractedStrings, setExtractedStrings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [minLength, setMinLength] = useState(4);
  const [showStrings, setShowStrings] = useState(false);

  const handleExtractStrings = async () => {
    // Si la 'prop' del archivo no existe, muestra un error
    if (!file) {
      setError("No se recibió un archivo para procesar.");
      return;
    }

    setLoading(true);
    setError(null);
    setExtractedStrings([]);
    setShowStrings(false);

    try {
      const arrayBuffer = await file.arrayBuffer(); // Usa directamente el método del objeto File
      const textContent = new TextDecoder('utf-8').decode(arrayBuffer);
      const regex = new RegExp(`[\\x20-\\x7E]{${minLength},}`, 'g');
      const foundStrings = textContent.match(regex) || [];

      setExtractedStrings(foundStrings);
      setShowStrings(true);
    } catch (e) {
      console.error("Error durante la extracción de strings:", e);
      setError("Error al procesar el archivo. Intenta de nuevo.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col min-w-full h-full p-6 bg-white dark:bg-slate-950 rounded-xl shadow-sm border border-gray-200 dark:border-slate-800">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Extractor de Strings
      </h2>

      <div className="mb-4 space-y-4">
        <div>
          <label htmlFor="min-length" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Mínimo de caracteres:
          </label>
          <input
            id="min-length"
            type="number"
            value={minLength}
            onChange={(e) => setMinLength(Math.max(1, Number(e.target.value)))}
            min="1"
            className="w-full rounded-md border-gray-300 dark:border-slate-700 bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-gray-100 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
          />
        </div>

        <button
          onClick={handleExtractStrings}
          disabled={loading || !file} // Deshabilita el botón si no hay un archivo
          className="w-full py-2 px-4 rounded-full text-sm font-semibold border-0
            bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-300 dark:hover:bg-blue-800
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Extrayendo...' : 'Extraer Strings'}
        </button>
      </div>

      {loading && (
        <div className="flex justify-center items-center h-full text-gray-500">
          Extrayendo strings... Esto puede tardar si el archivo es grande.
        </div>
      )}

      {error && (
        <div className="text-red-500 text-center">{error}</div>
      )}

      {showStrings && extractedStrings.length > 0 && (
        <div className="mt-4 p-4 bg-gray-100 dark:bg-slate-800 rounded-md overflow-y-auto flex-grow">
          <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-2">Strings Extraídos:</h3>
          <ul className="list-disc list-inside space-y-1 text-sm text-gray-600 dark:text-gray-300">
            {extractedStrings.map((str, index) => (
              <li key={index} className="font-mono break-all">{str}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
function FromHexConverter({ file }) {
  const [decodedData, setDecodedData] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchSequence, setSearchSequence] = useState('');
  const [highlightedData, setHighlightedData] = useState(null);
  const [searchInfo, setSearchInfo] = useState(null);

  const handleDecodeHex = async () => {
    if (!file) {
      setError("No se recibió un archivo para procesar.");
      return;
    }
    setLoading(true);
    setError(null);
    setDecodedData('');
    setHighlightedData(null);

    try {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const hexString = e.target.result.trim();
          const cleanHexString = hexString.replace(/[^0-9a-fA-F]/g, '');
          if (cleanHexString.length === 0 || cleanHexString.length % 2 !== 0) {
            setError("El contenido hexadecimal es de longitud impar o no contiene datos válidos.");
            return;
          }
          let decoded = '';
          for (let i = 0; i < cleanHexString.length; i += 2) {
            decoded += String.fromCharCode(parseInt(cleanHexString.substr(i, 2), 16));
          }
          setDecodedData(decoded);
        } catch (err) {
          setError("Error al decodificar el contenido hexadecimal.");
          console.error(err);
        } finally {
          setLoading(false);
        }
      };
      reader.onerror = () => {
        setError("Error al leer el archivo.");
        setLoading(false);
      };
      reader.readAsText(file);
    } catch (e) {
      console.error("Error general:", e);
      setError("Ocurrió un error inesperado.");
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (!decodedData || !searchSequence) {
      setHighlightedData(null);
      setSearchInfo(null);
      return;
    }
    const needle = searchSequence;
    const hay = decodedData;
    const maxHighlights = 2000;
    const largeThreshold = 400000; // caracteres
    let parts = [];
    let last = 0;
    let count = 0;
    let lcNeedle = needle.toLowerCase();
    let lcHay = hay.toLowerCase();
    if (hay.length > largeThreshold) {
      // Búsqueda iterativa sin regex para evitar overhead
      let idx = lcHay.indexOf(lcNeedle);
      while (idx !== -1 && count < maxHighlights) {
        parts.push(hay.slice(last, idx));
        parts.push(<span key={idx} className="bg-yellow-300 dark:bg-yellow-600 text-black">{hay.slice(idx, idx + needle.length)}</span>);
        last = idx + needle.length;
        count++;
        idx = lcHay.indexOf(lcNeedle, last);
      }
      parts.push(hay.slice(last));
      setHighlightedData(parts);
      setSearchInfo(count >= maxHighlights ? `Se detuvo el resaltado tras ${maxHighlights} coincidencias (resultado truncado).` : `Coincidencias: ${count}`);
      return;
    }
    // Texto manejable: usar regex escapado para coincidencias completas (case-insensitive)
    const regex = new RegExp(escapeRegExp(needle), 'gi');
    let m;
    while ((m = regex.exec(hay)) !== null && count < maxHighlights) {
      parts.push(hay.slice(last, m.index));
      parts.push(<span key={m.index} className="bg-yellow-300 dark:bg-yellow-600 text-black">{m[0]}</span>);
      last = m.index + m[0].length;
      count++;
    }
    parts.push(hay.slice(last));
    setHighlightedData(parts);
    setSearchInfo(count >= maxHighlights ? `Se detuvo el resaltado tras ${maxHighlights} coincidencias (resultado truncado).` : `Coincidencias: ${count}`);
  };

  return (
    <div className="flex flex-col h-full p-6 bg-white dark:bg-slate-950 rounded-xl shadow-sm border border-gray-200 dark:border-slate-800">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Convertidor From Hex
      </h2>

      <div className="mb-4">
        <button
          onClick={handleDecodeHex}
          disabled={loading || !file}
          className="w-full py-2 px-4 rounded-full text-sm font-semibold border-0
            bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-300 dark:hover:bg-blue-800
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Decodificando...' : 'Decodificar de Hex'}
        </button>
      </div>

      {decodedData && (
        <div className="mb-4">
          <label htmlFor="search-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Buscar secuencia:
          </label>
          <div className="flex space-x-2">
            <input
              id="search-input"
              type="text"
              value={searchSequence}
              onChange={(e) => setSearchSequence(e.target.value)}
              placeholder="Ej. mi_contraseña"
              className="w-full rounded-md border-gray-300 dark:border-slate-700 bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-gray-100 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            />
            <button
              onClick={handleSearch}
              className="py-2 px-4 rounded-full text-sm font-semibold border-0
                bg-green-50 text-green-700 hover:bg-green-100 dark:bg-green-900 dark:text-green-300 dark:hover:bg-green-800"
            >
              Buscar
            </button>
          </div>
        </div>
      )}

      {loading && <div className="flex justify-center items-center h-full text-gray-500">Decodificando...</div>}
      {error && <div className="text-red-500 text-center">{error}</div>}

      {decodedData && (
        <div className="mt-4 p-4 bg-gray-100 dark:bg-slate-800 rounded-md overflow-y-auto flex-grow">
          <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-2">Datos Decodificados:</h3>
          {searchInfo && <div className="text-xs mb-2 text-gray-500 dark:text-gray-400">{searchInfo}</div>}
          <pre className="font-mono whitespace-pre-wrap break-all text-sm text-gray-600 dark:text-gray-300">
            {highlightedData || decodedData}
          </pre>
        </div>
      )}
    </div>
  );
}


function ToHexConverter({ file }) {
  const [hexData, setHexData] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchSequence, setSearchSequence] = useState('');
  const [highlightedData, setHighlightedData] = useState(null);
  const [searchInfo, setSearchInfo] = useState(null);

  const handleConvertToHex = async () => {
    if (!file) {
      setError("No se recibió un archivo para procesar.");
      return;
    }
    setLoading(true);
    setError(null);
    setHexData('');
    setHighlightedData(null);

    try {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const buffer = e.target.result;
          const uint8Array = new Uint8Array(buffer);
          let hexString = '';
          for (let i = 0; i < uint8Array.length; i++) {
            hexString += uint8Array[i].toString(16).padStart(2, '0');
            hexString += ' ';
          }
          setHexData(hexString.trim());
        } catch (err) {
          setError("Error al convertir el archivo a hexadecimal.");
          console.error(err);
        } finally {
          setLoading(false);
        }
      };
      reader.onerror = () => {
        setError("Error al leer el archivo.");
        setLoading(false);
      };
      reader.readAsArrayBuffer(file);
    } catch (e) {
      console.error("Ocurrió un error inesperado:", e);
      setError("Ocurrió un error inesperado.");
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (!hexData || !searchSequence) {
      setHighlightedData(null);
      setSearchInfo(null);
      return;
    }
    const cleanHexData = hexData.replace(/\s/g, '').toLowerCase();
    const target = searchSequence.replace(/\s/g, '').toLowerCase();

    if (!/^[0-9a-fA-F]+$/.test(target) || target.length % 2 !== 0) {
      setError("La secuencia de búsqueda no es un hexadecimal válido (debe tener longitud par y dígitos hex).");
      setHighlightedData(null);
      setSearchInfo(null);
      return;
    }

    // Precomputar mapa de índices entre la cadena sin espacios y la original
    const map = []; // map[posEnClean] = indiceEnOriginal
    for (let i = 0, j = 0; i < hexData.length; i++) {
      const c = hexData[i];
      if (c !== ' ') {
        map[j] = i;
        j++;
      }
    }
    const parts = [];
    let lastOriginal = 0;
    let count = 0;
    const maxHighlights = 2000;
    let idx = cleanHexData.indexOf(target);
    while (idx !== -1 && count < maxHighlights) {
      const end = idx + target.length; // índices en clean
      const originalStart = map[idx];
      const originalEnd = map[end - 1] + 2; // +1 para incluir último char, +1 para que substring sea exclusivo
      parts.push(hexData.slice(lastOriginal, originalStart));
      parts.push(<span key={originalStart} className="bg-yellow-300 dark:bg-yellow-600 text-black">{hexData.slice(originalStart, originalEnd)}</span>);
      lastOriginal = originalEnd;
      count++;
      idx = cleanHexData.indexOf(target, end);
    }
    parts.push(hexData.slice(lastOriginal));
    setHighlightedData(parts);
    setSearchInfo(count >= maxHighlights ? `Se detuvo tras ${maxHighlights} coincidencias (truncado).` : `Coincidencias: ${count}`);
  };

  return (
    <div className="flex flex-col h-full p-6 bg-white dark:bg-slate-950 rounded-xl shadow-sm border border-gray-200 dark:border-slate-800">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Convertidor To Hex
      </h2>

      <div className="mb-4">
        <button
          onClick={handleConvertToHex}
          disabled={loading || !file}
          className="w-full py-2 px-4 rounded-full text-sm font-semibold border-0
            bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-300 dark:hover:bg-blue-800
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Convirtiendo...' : 'Convertir a Hex'}
        </button>
      </div>

      {hexData && (
        <div className="mb-4">
          <label htmlFor="search-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Buscar secuencia:
          </label>
          <div className="flex space-x-2">
            <input
              id="search-input"
              type="text"
              value={searchSequence}
              onChange={(e) => setSearchSequence(e.target.value)}
              placeholder="Ej. 48656c6c6f"
              className="w-full rounded-md border-gray-300 dark:border-slate-700 bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-gray-100 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
            />
            <button
              onClick={handleSearch}
              className="py-2 px-4 rounded-full text-sm font-semibold border-0
                bg-green-50 text-green-700 hover:bg-green-100 dark:bg-green-900 dark:text-green-300 dark:hover:bg-green-800"
            >
              Buscar
            </button>
          </div>
        </div>
      )}

      {loading && <div className="flex justify-center items-center h-full text-gray-500">Convirtiendo...</div>}
      {error && <div className="text-red-500 text-center">{error}</div>}

      {hexData && (
        <div className="mt-4 p-4 bg-gray-100 dark:bg-slate-800 rounded-md overflow-y-auto flex-grow">
          <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-2">Datos en Hexadecimal:</h3>
          {searchInfo && <div className="text-xs mb-2 text-gray-500 dark:text-gray-400">{searchInfo}</div>}
          <pre className="font-mono whitespace-pre-wrap break-all text-sm text-gray-600 dark:text-gray-300">
            {highlightedData || hexData}
          </pre>
        </div>
      )}
    </div>
  );
}


function HexdumpViewer({ file }) {
  const [hexdump, setHexdump] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleHexdump = async () => {
    if (!file) {
      setError("No se recibió un archivo para procesar.");
      return;
    }

    setLoading(true);
    setError(null);
    setHexdump('');

    try {
      const reader = new FileReader();

      reader.onload = (e) => {
        try {
          const buffer = e.target.result;
          const uint8Array = new Uint8Array(buffer);

          let output = '';
          const bytesPerLine = 16;

          for (let i = 0; i < uint8Array.length; i += bytesPerLine) {
            // Address (left side)
            const address = i.toString(16).padStart(8, '0');
            output += `${address}  `;

            // Hex values (middle)
            let hexBytes = '';
            for (let j = 0; j < bytesPerLine; j++) {
              if (i + j < uint8Array.length) {
                hexBytes += uint8Array[i + j].toString(16).padStart(2, '0') + ' ';
              } else {
                hexBytes += '   '; // Pad with spaces for short lines
              }
            }
            output += `${hexBytes} `;

            // ASCII characters (right side)
            let asciiChars = '';
            for (let j = 0; j < bytesPerLine; j++) {
              if (i + j < uint8Array.length) {
                const charCode = uint8Array[i + j];
                // Check if the character is printable (from space to tilde)
                if (charCode >= 32 && charCode <= 126) {
                  asciiChars += String.fromCharCode(charCode);
                } else {
                  asciiChars += '.'; // Use a dot for non-printable characters
                }
              }
            }
            output += `|${asciiChars}|\n`;
          }

          setHexdump(output);
        } catch (err) {
          setError("Error al generar el hexdump.");
          console.error(err);
        } finally {
          setLoading(false);
        }
      };

      reader.onerror = () => {
        setError("Error al leer el archivo.");
        setLoading(false);
      };

      reader.readAsArrayBuffer(file);
    } catch (e) {
      console.error("Ocurrió un error inesperado:", e);
      setError("Ocurrió un error inesperado.");
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full p-6 bg-white dark:bg-slate-950 rounded-xl shadow-sm border border-gray-200 dark:border-slate-800">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Visor Hexdump
      </h2>

      <div className="mb-4">
        <button
          onClick={handleHexdump}
          disabled={loading || !file}
          className="w-full py-2 px-4 rounded-full text-sm font-semibold border-0
            bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-300 dark:hover:bg-blue-800
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Generando...' : 'Generar Hexdump'}
        </button>
      </div>

      {loading && (
        <div className="flex justify-center items-center h-full text-gray-500">
          Generando hexdump...
        </div>
      )}

      {error && (
        <div className="text-red-500 text-center">{error}</div>
      )}

      {hexdump && (
        <div className="mt-4 p-4 bg-gray-100 dark:bg-slate-800 rounded-md overflow-y-auto flex-grow">
          <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-2">Hexdump del Archivo:</h3>
          <pre className="font-mono text-sm text-gray-600 dark:text-gray-300">
            {hexdump}
          </pre>
        </div>
      )}
    </div>
  );
}
function RegexExtractor({ file }) {
  const [extractedMatches, setExtractedMatches] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [regexPattern, setRegexPattern] = useState('');
  const [flags, setFlags] = useState('g'); // 'g' for global search, a common choice

  const handleExtractMatches = async () => {
    if (!file) {
      setError("No se recibió un archivo para procesar.");
      return;
    }

    if (!regexPattern) {
      setError("Por favor, ingresa una expresión regular.");
      return;
    }

    setLoading(true);
    setError(null);
    setExtractedMatches([]);

    try {
      const reader = new FileReader();

      reader.onload = (e) => {
        try {
          const textContent = e.target.result;

          // Use a new RegExp object to allow user-defined flags
          const regex = new RegExp(regexPattern, flags);

          // Find all matches in the text content
          const foundMatches = textContent.match(regex) || [];

          setExtractedMatches(foundMatches);
        } catch (e) {
          setError("Error en la expresión regular. Por favor, revisa la sintaxis.");
          console.error("Error with regex:", e);
        } finally {
          setLoading(false);
        }
      };

      reader.onerror = () => {
        setError("Error al leer el archivo.");
        setLoading(false);
      };

      reader.readAsText(file);

    } catch (e) {
      console.error("Error general:", e);
      setError("Ocurrió un error inesperado.");
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full p-6 bg-white dark:bg-slate-950 rounded-xl shadow-sm border border-gray-200 dark:border-slate-800">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Extractor por Expresión Regular
      </h2>

      <div className="mb-4 space-y-4">
        <div>
          <label htmlFor="regex-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Expresión Regular:
          </label>
          <input
            id="regex-input"
            type="text"
            value={regexPattern}
            onChange={(e) => setRegexPattern(e.target.value)}
            placeholder="Ej. \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            className="w-full rounded-md border-gray-300 dark:border-slate-700 bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-gray-100 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
          />
        </div>

        <div>
          <label htmlFor="flags-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Flags (opcional):
          </label>
          <input
            id="flags-input"
            type="text"
            value={flags}
            onChange={(e) => setFlags(e.target.value)}
            placeholder="g, i, m, etc."
            className="w-full rounded-md border-gray-300 dark:border-slate-700 bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-gray-100 shadow-sm focus:border-blue-500 focus:ring-blue-500 text-sm"
          />
        </div>

        <button
          onClick={handleExtractMatches}
          disabled={loading || !file || !regexPattern}
          className="w-full py-2 px-4 rounded-full text-sm font-semibold border-0
            bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900 dark:text-blue-300 dark:hover:bg-blue-800
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Buscando...' : 'Buscar'}
        </button>
      </div>

      {loading && (
        <div className="flex justify-center items-center h-full text-gray-500">
          Buscando coincidencias...
        </div>
      )}

      {error && (
        <div className="text-red-500 text-center">{error}</div>
      )}

      {extractedMatches.length > 0 && (
        <div className="mt-4 p-4 bg-gray-100 dark:bg-slate-800 rounded-md overflow-y-auto flex-grow">
          <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-2">Coincidencias Encontradas:</h3>
          <ul className="list-disc list-inside space-y-1 text-sm text-gray-600 dark:text-gray-300">
            {extractedMatches.map((match, index) => (
              <li key={index} className="font-mono break-all">{match}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
export default ToolSelector;