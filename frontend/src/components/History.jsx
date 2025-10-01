// History.jsx
import {useState, useEffect} from 'react';
import axios from 'axios';
import { TrashIcon } from '@heroicons/react/24/solid'
import { DocumentArrowDownIcon } from '@heroicons/react/24/solid'
function getStoredUser() {
  try {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  } catch (error) {
    console.error('Error al obtener el usuario de localStorage:', error);
    return null;
  }
}

async function getUserHistory() {
  const user = getStoredUser();
  if (!user) {
    console.error('No hay usuario autenticado.');
    return [];
  }
  try {
    const { data } = await axios.get(`http://localhost:3001/api/history/${user.user_id}`);
    return data;
  } catch (error) {
    console.error('Error al obtener el historial:', error);
    return [];
  }
}

const History = () => {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);

  useEffect(() => {
    const fetchFiles = async () => {
      setIsLoading(true);
      const userHistory = await getUserHistory();
      setHistory(userHistory);
      setIsLoading(false);
    };

    fetchFiles();
  }, []); 
  function getEstado(row){
    if(row.scan_id == null){
      return 'Error'; // no se generó escaneo
    }
    if(typeof row.vt_score === 'number' && row.vt_score > 0){
      return 'Malicioso';
    }
    if(typeof row.vt_score === 'number'){
      return 'Seguro';
    }
    return 'Error';
  }

  function formatDate(ts){
    if(!ts) return 'N/A';
    return new Date(ts).toLocaleString();
  }

  async function handleDownloadReport(row){
    if(!row.scan_report){
      return;
    }
    try{
      setDownloadingId(row.scan_id);
      // Asegura que sea string
      const jsonString = typeof row.scan_report === 'string' ? row.scan_report : JSON.stringify(row.scan_report);
      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${row.file_name || 'reporte'}_${row.scan_id || 'scan'}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }finally{
      setDownloadingId(null);
    }
  }
  async function handlDeleteFile(row){
    if(!row.file_id){
      return;
    }
    try{
      setIsLoading(true);
      console.log('intento', row.file_id);
      await axios.delete(`http://localhost:3001/api/files/${row.file_id}`);
      // Refrescar historial
      const userHistory = await getUserHistory();
      setHistory(userHistory);
    }catch(err){
      alert('Error al eliminar el archivo. Intente nuevamente.');
    }finally{
      setIsLoading(false);
    }
  }

  const filteredHistory = history.filter(h => !filter || h.file_name?.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm flex flex-col border border-gray-200 dark:border-slate-800 h-full max-h-full overflow-hidden">
      <h2 className="text-xl font-bold text-gray-800 dark:text-gray-200 mb-4">
        Historial de Archivos Escaneados
      </h2>
      <div className="flex items-center gap-4 mb-4">
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filtrar por nombre" className="px-3 py-2 rounded-md border border-gray-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm text-gray-700 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500" />
        <button onClick={()=>{setIsLoading(true); getUserHistory().then(d=>{setHistory(d); setIsLoading(false);});}} className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50">Refrescar</button>
      </div>
      
      {isLoading ? (
        <div className="flex-grow flex items-center justify-center text-gray-400 dark:text-gray-500 text-center">
          <p>Cargando...</p>
        </div>
      ) : filteredHistory.length === 0 ? (
        <div className="flex-grow flex items-center justify-center text-gray-400 dark:text-gray-500 text-center">
          <p>No hay archivos en el historial.</p>
        </div>
      ) : (
        <div className="overflow-x-auto h-full">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-800">
            <thead className="bg-gray-50 dark:bg-slate-900 sticky top-0">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Nombre del Archivo
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Usuario
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Estado
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Detecciones
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Fecha y Hora
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Opciones
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-950 divide-y divide-gray-200 dark:divide-slate-800">
              {filteredHistory.map((item, index) => {
                const estado = getEstado(item);
                return (
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-slate-900">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-gray-100">
                      {item.file_name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">
                      {item.user_name || item.user_email || 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {estado === 'Malicioso' && (
                        <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300">Malicioso</span>
                      )}
                      {estado === 'Seguro' && (
                        <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">Seguro</span>
                      )}
                      {estado === 'Error' && (
                        <span className="px-2.5 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">Error</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-300">
                      {typeof item.vt_score === 'number' ? item.vt_score : '0'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {formatDate(item.scan_timestamp || item.uploaded_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                      <TrashIcon onClick={()=>handlDeleteFile(item)} className='size-4 cursor-pointer hover:text-red-700 transition-color duration-300 ease-in-out' title='eliminar'/>
                      {item.scan_report ? <DocumentArrowDownIcon className='size-4 cursor-pointer hover:text-blue-700 transition-color duration-300 ease-in-out' title={downloadingId===item.scan_id ? 'Descargando...' : 'Descargar'} onClick={()=>handleDownloadReport(item)} disabled={downloadingId===item.scan_id}/> : <span className="text-gray-400">—</span>}  
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default History;