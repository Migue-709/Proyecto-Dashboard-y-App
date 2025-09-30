import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Illustration from '../components/illustration';
import { validateSignInForm } from '../components/utils/validation';
const Login = ({ setUser }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [validationError, seValidationError] = useState(null);

  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    const validation = validateSignInForm(email, password);
    if (validation) {
      seValidationError(validation);
      setIsLoading(false);
      return;
    }
    try {
      const response = await fetch('http://localhost:3001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await response.json();
      setIsLoading(false);
      if (!response.ok) {
        setError(data.error || 'Error al iniciar sesión');
        return;
      }
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setUser(data.user);
      window.location.href = '/dashboard';
    } catch (err) {
      setIsLoading(false);
      setError('Error de conexión con el servidor');
    }
  };

  return (
    <div className="h-screen w-full flex flex-col md:flex-row items-center justify-center bg-gray-50">

      {/* CLAVE 2: Contenedor de Contenido. h-full y w-full para ocupar el espacio del padre */}
      <div className="w-full h-full bg-white shadow-2xl flex flex-col md:flex-row overflow-hidden">

        {/* Columna Izquierda: Ilustración (Ocupa la mitad del espacio) */}
        <div className="block lg:w-1/2">
          <Illustration />
        </div>

        {/* Columna Derecha: Formulario (Ocupa el 100% en móvil, la mitad en desktop) */}
        <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12">

          <div className="w-full max-w-lg">
            <h2 className="text-4xl font-extrabold text-gray-900 mb-2 text-center">
              Iniciar Sesión
            </h2>
            <p className="text-gray-500 mb-8 text-center">
              Accede a <strong>MalwareScan</strong> y protege tus archivos hoy.
            </p>

            <form className="space-y-6" onSubmit={handleSubmit}>

              {error && (
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm">
                  {error}
                </div>
              )}
              {validationError && (
                <ul className='flex flex-col items-center justify-start gap-1' >
                  {validationError.email && <li className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">{validationError.email}</li>}
                  {validationError.password && <li className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">{validationError.password}</li>}
                </ul>
              )}

              {/* Campo Email */}
              <div>
                <div className="relative">
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Correo Electrónico"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v-6m0 6h6m-6 0v6M4 4h16v16H4V4z" /></svg>
                </div>
              </div>

              {/* Campo Contraseña */}
              <div className='flex flex-col gap-2'>
                <div className="relative">
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'} // CLAVE 1: Cambia el tipo según showPassword
                    required
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Contraseña"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6-4h12V9H6v4z" /></svg>
                </div>
                <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="h-full w-full flex items-center justify-start text-blue-800 hover:text-blue-900 rounded-r-lg transition duration-150"
                                            aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                                        >
                                            {/* CLAVE 3: El icono es condicional */}
                                            {showPassword ? (
                                                <div className='flex items-center space-x-1'> {/* Usa flex y space-x-1 para espaciado */}

                                                    <svg className='size-5' xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 8.2A10.5 10.5 0 0 0 2 12a10.5 10.5 0 0 0 12.9 7.1M6.2 6.2A10.5 10.5 0 0 1 12 4.5c4.8 0 8.8 3.2 10 7.5a10.5 10.5 0 0 1-4.2 5.8M6.2 6.2 3 3m3.2 3.2L10 10m7.9 7.9L21 21m-3.2-3.2L14 14m0 0A3 3 0 1 0 10 10M14 14 10 10" /></svg>
                                                    <small className='whitespace-nowrap font-medium'>Ocultar contraseña</small> {/* CLAVE: Evita el salto de línea */}
                                                </div>
                                            ) : (
                                                <div className='flex items-center space-x-1'> {/* Usa flex y space-x-1 para espaciado */}

                                                    <svg className="size-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                    </svg>
                                                    <small className='whitespace-nowrap font-medium'>Mostrar contraseña</small> {/* CLAVE: Evita el salto de línea */}
                                                </div>
                                            )}
                                        </button>
              </div>
              {/* Botón de Submit */}
              <div>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full flex justify-center py-3 px-4 border border-transparent text-lg font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 transition duration-150"
                >
                  {isLoading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
                </button>
              </div>
            </form>

            {/* Enlace a Registro y Logins Sociales */}
            <div className="mt-8">
              <p className="text-center text-sm">
                ¿No tienes cuenta?{' '}
                <button
                  type="button"
                  className="font-semibold text-blue-600 hover:underline"
                  onClick={() => navigate('/register')}
                >
                  Crea una cuenta
                </button>
              </p>

              <div className="mt-6">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300"></div>
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">
                      MalwareScan
                    </span>
                  </div>
                </div>

                <a href='/' className="mt-4 flex justify-center space-x-3 hover:text-violet-500">
                  Volver a Inicio
                </a>
              </div>

            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;