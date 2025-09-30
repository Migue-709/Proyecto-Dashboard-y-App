import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Illustration from '../components/illustration';
import verified from '../assets/verified.svg';
import { validateRegistrationForm } from '../components/utils/validation';
import { generateSecurePassword } from '../components/utils/passwordGenerator';
import Message from '../components/Message';
const Register = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');
    const [validationError, seValidationError] = useState(null);
    const [confirmationSent, setConfirmationSent] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [showMsg, setShowMsg] = useState(false);
    const [showMsgEmail, setShowMsgEmail] = useState(false);
    const [msgTimer, setMsgTimer] = useState(null);
    const API_BASE = import.meta.env.VITE_AUTH_API_BASE || 'http://localhost:3001';
    const handleGeneratePassword = () => {
        const newPassword = generateSecurePassword(12);
        setPassword(newPassword);

        // 1. Limpiar cualquier temporizador anterior
        if (msgTimer) {
            clearTimeout(msgTimer);
        }

        navigator.clipboard.writeText(newPassword)
            .then(() => {
                // 2. Mostrar el mensaje
                setShowMsg(true);

                // 3. Establecer un temporizador para ocultar el mensaje (ej: 3000ms = 3 segundos)
                const timerId = setTimeout(() => {
                    setShowMsg(false);
                }, 3000); // <-- CLAVE: Ocultar después de 3 segundos

                // 4. Guardar el ID del temporizador
                setMsgTimer(timerId);

            })
            .catch(err => {
                console.error('Error al copiar: ', err);
                // Si usas un fallback que tiene su propia alerta o mensaje, úsalo aquí.
                // Si no, aquí deberías mostrar un mensaje de error.
                setShowMsg(false);
            });

    };
    // Manejador de Registro
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);
        seValidationError(null); // limpiar errores previos
        const validation = validateRegistrationForm(name, email, password);
        if (validation) { // ahora sólo será truthy si hay errores reales
            seValidationError(validation);
            setIsLoading(false);
            return;
        }

        try {
            const response = await fetch(`${API_BASE}/api/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password })
            });
            const data = await response.json();

            setIsLoading(false);

            if (!response.ok) {
                setError(data.error || 'Error al registrar usuario. Inténtalo de nuevo.');
                return;
            }
            // El backend ya envía el correo de verificación en /api/register.
            // Antes aquí se llamaba a handleResendEmail(), provocando un segundo correo
            // y anulando el token anterior. Se elimina para evitar duplicados.
            setConfirmationSent(true);
            // Opcional: mostrar mensaje reutilizando el mismo componente visual
            setShowMsgEmail(true);
        } catch (err) {
            setIsLoading(false);
            setError('Error de conexión con el servidor. Verifica tu conexión.');
        }
    };

    // Manejador para Reenviar Correo
    const handleResendEmail = async () => {
        setError('');
        try {
            const r = await fetch(`${API_BASE}/api/users/resend-verification`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const d = await r.json();
            if (!r.ok) {
                setError(d.error || 'No se pudo reenviar el correo de verificación.');
            } else {
                setError('');
                setShowMsgEmail(true)
            }
        } catch (e) {
            setError('Error de conexión al reenviar el correo.');
        }
    };
    const handleMessageAnimationComplete = () => {
        setShowMsg(false)
    };


    return (
        // Contenedor principal: 100% de la vista
        <div className="h-screen w-full flex items-center justify-center bg-gray-50">

            {/* Contenedor de Contenido: Diseño de dos columnas */}
            <div className="w-full h-full bg-white shadow-2xl flex flex-col md:flex-row overflow-hidden">

                {/* Columna 1: Ilustración (Visible solo en desktop) */}
                <div className="block lg:w-1/2">
                    {confirmationSent ? <img src={verified} className="w-screen h-[27vh] md:size-full transition-all duration-500 ease-in-out" /> : <Illustration />}

                </div>

                {/* Columna 2: Formulario / Mensaje de Confirmación */}
                <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12">

                    <div className="w-full max-w-lg">

                        {/* LÓGICA CONDICIONAL: Mostrar Formulario O Mensaje de Éxito */}
                        {confirmationSent ? (

                            /* CONTENIDO DE VERIFICACIÓN (Mensaje de Éxito) */
                            <div className="text-center space-y-6 p-8 bg-blue-50 rounded-lg border border-blue-200">
                                <svg className="w-12 h-12 mx-auto text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8m-17 10h18a2 2 0 002-2V6a2 2 0 00-2-2H3a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                                <div className="text-gray-800 font-semibold text-lg">
                                    ¡Registro exitoso!
                                </div>
                                <p className="text-gray-600 text-sm">
                                    Se ha enviado un correo de verificación a <b>{email}</b>.<br />
                                    Revisa tu bandeja de entrada y carpeta de spam para activar tu cuenta.
                                </p>
                                <button
                                    type="button"
                                    onClick={handleResendEmail}
                                    className="text-sm font-medium text-blue-600 hover:text-blue-500 underline"
                                >
                                    ¿No recibiste el correo? Reenviar verificación
                                </button>
                                <p className="mt-4 text-sm text-gray-500">
                                    <Link to="/login" className="font-semibold text-blue-600 hover:text-blue-500">
                                        Ir a Iniciar Sesión
                                    </Link>
                                </p>
                            </div>

                        ) : (

                            /* CONTENIDO DEL FORMULARIO DE REGISTRO */
                            <>
                                <h2 className="text-4xl font-extrabold text-gray-900 mb-2 text-center">
                                    Crear Cuenta
                                </h2>
                                <p className="text-gray-500 mb-8 text-center">
                                    Comienza con <strong>MalwareScan</strong> y protege tus archivos hoy.
                                </p>

                                {error && (
                                    <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">
                                        {error}
                                    </div>
                                )}
                                {validationError != null && (
                                    <ul className='flex flex-col items-center justify-start gap-1' >
                                        {validationError.name && <li className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">{validationError.name}</li>}
                                        {validationError.email && <li className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">{validationError.email}</li>}
                                        {validationError.password && <li className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-sm mb-6">{validationError.password}</li>}
                                    </ul>
                                )}

                                <form className="space-y-6" onSubmit={handleSubmit}>

                                    {/* Campo Nombre */}
                                    <div>
                                        <div className="relative">
                                            <input
                                                id="name"
                                                name="name"
                                                type="text"
                                                className="w-full pl-10 pr-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                                placeholder="Primer Nombre"
                                                value={name}
                                                onChange={(e) => setName(e.target.value)}
                                                disabled={isLoading}
                                            />
                                            <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                                        </div>
                                    </div>

                                    {/* Campo Email */}
                                    <div>
                                        <div className="relative">
                                            <input
                                                id="email"
                                                name="email"
                                                type="email"
                                                className="w-full pl-10 pr-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                                placeholder="Correo Electrónico"
                                                value={email}
                                                onChange={(e) => setEmail(e.target.value)}
                                                disabled={isLoading}
                                            />
                                            <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8m-17 10h18a2 2 0 002-2V6a2 2 0 00-2-2H3a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                                        </div>
                                    </div>

                                    {/* Campo Contraseña */}
                                    <div className='flex flex-col  gap-2  w-full '>
                                        <div className="relative">
                                            <input
                                                id="password"
                                                name="password"
                                                type={showPassword ? 'text' : 'password'}
                                                maxLength={20} // Usar límite máximo seguro
                                                // ... (clases para borde y foco)
                                                className="w-full pl-10 pr-24 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-lg focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                                                placeholder="Crea una Contraseña Segura"
                                                value={password}
                                                onChange={(e) => setPassword(e.target.value)}
                                                disabled={isLoading}
                                            />
                                            <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 size-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6-4h12V9H6v4z" /></svg>
                                            {/* Botón de Generar Clave */}
                                            <button
                                                type="button"
                                                onClick={handleGeneratePassword}
                                                className="absolute right-0 top-0 h-full px-3 text-sm font-medium text-blue-600 hover:text-blue-700 bg-gray-100 border-l border-gray-300 rounded-r-lg transition duration-150"
                                                disabled={isLoading}
                                            >
                                                Generar
                                            </button>

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
                                            {isLoading ? 'Registrando...' : 'Registrarse'}
                                        </button>
                                    </div>
                                </form>

                                {/* Enlace a Login y Pie de Página */}
                                <div className="mt-8">
                                    <p className="text-center text-sm">
                                        ¿Ya tienes una cuenta?{' '}
                                        <Link to="/login" className="font-semibold text-blue-600 hover:underline">
                                            Inicia sesión aquí
                                        </Link>
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

                                        <div className="mt-4 text-center">
                                            <Link to='/' className="text-sm font-medium text-gray-600 hover:text-blue-500 transition-colors">
                                                Volver a Inicio
                                            </Link>
                                        </div>
                                    </div>
                                </div>
                            </>
                        )}
                    </div>
                </div>
            </div>
            {showMsg && <Message msg={"Contraseña copiada en portapeles!"} onComplete={handleMessageAnimationComplete} />}
            {showMsgEmail && <Message msg={"Correo enviado. Revisa tu bandeja de entrada."} onComplete={()=>setShowMsgEmail(false)} />}
        </div>
    );
};

export default Register;