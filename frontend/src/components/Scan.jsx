import Gemini from "./Gemini";
function Scan({ file, maliciousCount, analysisResult, isScanning, quicksand }) {
  return (
    <div className="flex flex-col gap-6  h-full">
      {/* Sección de Resultados (Placeholder) */}
      {/* Este div permanece igual, ya que muestra los resultados detallados */}
      <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm flex flex-col border border-gray-200 dark:border-slate-800 overflow-hidden flex-grow">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Resultados del análisis</h3>
          <Gemini></Gemini>
          {analysisResult && (
            <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${maliciousCount > 0
              ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
              : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
              }`}>
              {maliciousCount > 0 ? 'Archivo malicioso' : 'Archivo seguro'}
            </span>
          )}
        </div>

        {!analysisResult || !file ? (
          <div className="flex-grow flex items-center justify-center text-gray-400 dark:text-gray-500">
            <div className="text-center">
              {isScanning ? (
                // Mostrar spinner y mensaje de carga mientras se escanea
                <div className="flex flex-col items-center">
                  <svg className="animate-spin h-12 w-12 text-gray-800 dark:text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  <span className="mt-4 text-lg font-medium text-gray-800 dark:text-gray-200">
                    Escaneando archivo...
                  </span>
                </div>
              ) : (
                // Mensaje predeterminado si no hay resultados y no se está escaneando
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-12 w-12 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-lg text-gray-500 dark:text-gray-400">
                    Aquí se mostrarán los resultados de su análisis.
                  </p>
                </>
              )}
            </div>
          </div>

        ) : (
          <div className="overflow-hidden flex flex-col ma-h-full  md:max-h-[300px] lg:max-h-[350px]">
            <div className="overflow-y-auto flex-grow">
              <Quicksand state={quicksand.state} results={Object.keys(quicksand.results)}/>


              <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-800">
                <caption className="px-4 py-2  text-lg font-semibold text-gray-900 dark:text-gray-100 uppercase w-full text-center">
                  RESULTADO DE VIRUSTOTAL
                </caption>
                <thead className="bg-gray-50 dark:bg-slate-900 sticky top-0">
                  <tr>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Motor
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Resultado
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Categoría
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Actualización
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-slate-950 divide-y divide-gray-200 dark:divide-slate-800">
                  {Object.keys(analysisResult).map((engineKey) => {
                    const engine = analysisResult[engineKey];
                    return (
                      <tr key={engine.engine_name} className="hover:bg-gray-50 dark:hover:bg-slate-900">
                        <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                          {engine.engine_name}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                          {engine.result || 'N/A'}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-sm">
                          <span className={`px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full
                                  ${engine.category === 'malicious' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300' :
                              engine.category === 'undetected' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' :
                                'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                            }`}
                          >
                            {engine.category}
                          </span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          {engine.engine_update}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
// Se asume que Quicksand recibe 'state' (el riesgo general) y 'results' (el objeto de resultados detallados)
function Quicksand({ state, results }) {
    
    // 1. Validar si el objeto 'results' existe y está vacío.
    const hasResults = results && Object.keys(results).length > 0;

    // 2. Si QuickSand no encuentra nada, el objeto 'results' puede ser {}. 
    //    Si la API devuelve un resultado vacío, 'results' podría ser null.
    if (!hasResults) {
        return (
            // Mensaje de "vacío" o "sin resultados"
            <div className="w-full">
                <p className="px-4 py-3 text-center text-lg font-semibold text-gray-900 dark:text-gray-100">
                    RESULTADO DE QUICKSAND
                </p>
                <p className="text-center py-6 text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-slate-900 rounded-lg m-2">
                    ✅ Análisis completado. No se encontraron indicadores de riesgo detallados en el documento.
                </p>
            </div>
        );
    }

    // Si hay resultados, renderiza la tabla.
    // Usaremos Object.entries() para obtener [clave, valor] y mapear los resultados.
    
    // NOTA: QuickSand puede devolver un objeto como este:
    // {
    //   'archivo.doc': { risk: 'low', tags: ['vba', 'ole'], score: 5 },
    //   'flujo_0': { risk: 'none', tags: [], score: 0 }
    // }
    
    return (
        <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-800">
            <caption className="px-4 py-2 text-left text-lg font-semibold text-gray-900 dark:text-gray-100">
                RESULTADO DE QUICKSAND
            </caption>
            
            <thead className="bg-gray-50 dark:bg-slate-900 sticky top-0">
                <tr>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Ruta / Flujo
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Riesgo Detectado
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Puntuación (Score)
                    </th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Tags / Categorías
                    </th>
                </tr>
            </thead>
            
            {/* El Tbody va DESPUÉS del Thead */}
            <tbody className="bg-white dark:bg-slate-800 divide-y divide-gray-200 dark:divide-slate-800">
                {/* 3. Mapeo del objeto de resultados */}
                {Object.entries(results).map(([filePath, data]) => (
                    <tr key={filePath} className="hover:bg-gray-50 dark:hover:bg-slate-900">
                        
                        {/* Celda RUTA / Flujo (la clave del objeto) */}
                        <td className="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                            {filePath}
                        </td>
                        
                        {/* Celda RIESGO DETECTADO */}
                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                            {/* Usamos un color basado en la propiedad 'risk' del resultado detallado */}
                            <span className={`px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full
                                ${data.state === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300' :
                                 data.state === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300' :
                                 data.state === 'low' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' :
                                 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                                }`}
                            >
                                {data.stater.toUpperCase()}
                            </span>
                        </td>
                        
                        {/* Celda SCORE */}
                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {data.score}
                        </td>

                        {/* Celda TAGS / CATEGORÍAS */}
                        <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {/* Muestra las etiquetas separadas por coma, si existen */}
                            {data.tags && data.tags.join(', ')}
                        </td>
                        
                    </tr>
                ))}
            </tbody>
        </table>
    );
}

// export default Quicksand; // Descomenta si usas export default
export default Scan