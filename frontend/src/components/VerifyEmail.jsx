import { useState, useEffect, useRef } from 'react';
import { useSearchParams, Link } from 'react-router-dom';

// Permite configurar el backend desde .env (Vite usa prefijo VITE_)
const API_BASE = import.meta.env.VITE_AUTH_API_BASE || 'http://localhost:3001';

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState('pending'); // pending | success | already | error

  const ranRef = useRef(false); // Previene doble invocación en StrictMode (React 18)

  useEffect(() => {
    if (ranRef.current) return; // si ya corrió, no repetir
    ranRef.current = true;

    (async () => {
      const token = searchParams.get('token');
      if (!token) {
        setMessage('❌ Token de verificación no proporcionado');
        setStatus('error');
        setLoading(false);
        return;
      }
      try {
        const response = await fetch(`${API_BASE}/api/users/verify-email?token=${encodeURIComponent(token)}`);
        const data = await response.json();
        if (response.ok) {
          if (data.alreadyVerified) {
            setMessage('✅ Email ya estaba verificado. Ya puedes iniciar sesión.');
            setStatus('already');
          } else {
            setMessage('✅ Email verificado correctamente. Ya puedes iniciar sesión.');
            setStatus('success');
          }
        } else {
          setMessage('❌ Error: ' + data.error);
          setStatus('error');
        }
      } catch (error) {
        setMessage('❌ Error de conexión con el servidor');
        setStatus('error');
      } finally {
        setLoading(false);
      }
    })();
  }, [searchParams]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-slate-900 px-4">
      <div className="p-8 bg-white dark:bg-slate-950 rounded-xl shadow-lg border border-gray-200 dark:border-slate-800 w-full max-w-md">
        <h2 className="text-2xl font-bold mb-4 text-center text-slate-800 dark:text-slate-100">Verificación de Email</h2>
        {loading ? (
          <p className="text-center text-slate-600 dark:text-slate-300 animate-pulse">Verificando...</p>
        ) : (
          <div>
            <p className="text-center mb-6 text-sm font-medium text-slate-700 dark:text-slate-200 whitespace-pre-line">{message}</p>
            <div className="flex flex-col gap-3 items-center">
              {(status === 'success' || status === 'already') && (
                <Link to="/login" className="inline-block px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors cursor-pointer">
                  Ir al login
                </Link>
              )}
              <Link to="/register" className="text-xs text-slate-500 dark:text-slate-400 hover:underline">
                ¿No creaste esta cuenta? Regístrate
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default VerifyEmail;