import { useRef, useEffect } from 'react';
import { gsap } from 'gsap';

// ====================================================================
// DATOS Y COMPONENTES AUXILIARES
// ====================================================================

const NAMES = ["Da Rocha Manuel", "Francia Anyher", "Gutierrez Augusto", "Herrera José", "Molina Andrés", "Orozco Miguel", "Salcedo Juan",];
import heroImg from "/hero.svg" // Asegúrate de que esta ruta sea correcta

// 1. Ilustración Isométrica
const IsometricIllustration = () => (
    <div className="md:w-1/2 w-full flex justify-center md:justify-end">
        <img
            src={heroImg}
            alt="Ilustración de seguridad y escaneo de archivos"
            className="max-w-xs sm:max-w-sm md:max-w-md lg:max-w-lg w-full h-auto"
        />
    </div>
);

// 2. Componente para las Estadísticas (AJUSTE PARA MÓVIL)
const Statistics = () => (
    // CLAVE: Usamos 'flex-col' por defecto, y 'sm:flex-row' para tablet y desktop. 
    // Esto hace que en móvil se apilen, liberando espacio horizontal.
    <div className="flex flex-col sm:flex-row gap-8 mt-12 mb-16 items-center sm:items-start text-center sm:text-left">

        {/* 1. Motores de Escaneo */}
        <div className="flex flex-col">
            <span className="text-5xl font-bold tracking-tight text-gray-900">75+</span>
            <span className="text-gray-600 mt-1">Motores de Análisis Integrados</span>
        </div>

        {/* 2. Base de Datos */}
        <div className="flex flex-col">
            <span className="text-5xl font-bold tracking-tight text-gray-900">1.2M+</span>
            <span className="text-gray-600 mt-1">Firmas de Amenazas Conocidas</span>
        </div>

        {/* 3. Tasa de Detección */}
        <div className="flex flex-col">
            <span className="text-5xl font-bold tracking-tight text-gray-900">99.9%</span>
            <span className="text-gray-600 mt-1">Precisión en la Detección</span>
        </div>
    </div>
);

// 3. Componente Navbar (AJUSTE PARA MÓVIL)
const Navbar = () => (
    <nav className="container mx-auto px-4 py-6 flex justify-between items-center">
        <div className="flex items-center space-x-4 sm:space-x-12">
            <div className="text-xl font-bold text-gray-900">MalwareScan</div>

            {/* Ocultar links de navegación en móvil (pantallas pequeñas) */}
            <div className="hidden lg:flex space-x-6 text-gray-600">
                <a href="#" className="hover:text-gray-900">Producto</a>
                <a href="#" className="hover:text-gray-900">Tecnología</a>
                <a href="#" className="hover:text-gray-900">Confianza</a>
                <a href="#" className="hover:text-gray-900">Soporte</a>
            </div>
        </div>

        {/* CLAVE: Ocultar en móvil y mostrar en pantallas pequeñas hacia arriba */}
        <button className="hidden sm:block px-4 py-2 bg-blue-700 text-white font-semibold rounded-lg hover:bg-sky-800 transition-colors duration-300 ease-in-out cursor-pointer">
            <a href="/dashboard">Ir al Dashboard</a>
        </button>
    </nav>
);

// 4. Componente AnimatedNames
const AnimatedNames = () => {
    const nameRefs = useRef([]);
    nameRefs.current = [];

    const addToRefs = (el) => {
        if (el && !nameRefs.current.includes(el)) {
            nameRefs.current.push(el);
        }
    };

    useEffect(() => {
        const tl = gsap.timeline({
            repeat: -1,
            repeatDelay: 0,
        });

        gsap.set(nameRefs.current, { autoAlpha: 0, y: 10 });

        nameRefs.current.forEach((name, index) => {
            tl.to(name, {
                duration: 0.5,
                autoAlpha: 1,
                y: 0,
                ease: "power2.out",
            }, "+=0.5")
                .to(name, {
                    duration: 0.5,
                    autoAlpha: 0,
                    y: -10,
                    ease: "power2.in",
                }, "+=1.5");
        });

        return () => tl.kill();
    }, []);

    return (
        <div className="relative w-48 h-5 overflow-hidden flex-shrink-0">
            {NAMES.map((name) => (
                <span
                    key={name}
                    ref={addToRefs}
                    className="absolute top-0 left-0 font-bold whitespace-nowrap"
                >
                    {name}
                </span>
            ))}
        </div>
    );
};

// 5. Componente Footer
const Footer = () => (
    <>
        <div className="fixed bottom-0 left-0 w-full bg-white border-t border-gray-200 shadow-xl z-50">
            <div className="container mx-auto px-4 py-4 flex flex-col md:flex-row justify-between items-center text-sm">

                <div className="flex items-center space-x-2 mb-3 md:mb-0 text-gray-800">
                    <span>Desarrollado por</span>
                    <strong>Ing. Software II</strong>
                    <span>&copy; {new Date().getFullYear()}</span>
                </div>

                <div className="flex items-center space-x-2 mb-3 md:mb-0 text-gray-800">
                    <span>Colaboradores</span>
                    <div className="flex-shrink-0">
                        <AnimatedNames />
                    </div>
                </div>
            </div>
        </div>
    </>
);


// ====================================================================
// COMPONENTE PRINCIPAL: LandingPage
// ====================================================================

function LandingPage() {
    return (
        <div className="min-h-screen bg-white flex flex-col font-sans" >

            <Navbar />

            {/* HERO SECTION - Aseguramos padding y centrado en móvil */}
            <main className="container mx-auto px-4 py-8 sm:py-16 flex-grow flex items-center">

                <div className="flex flex-col md:flex-row items-center md:items-start gap-8 sm:gap-12 w-full">

                    {/* Contenido del Lado Izquierdo (Texto y CTA) */}
                    <div className="md:w-1/2 w-full text-center md:text-left mb-8 md:mb-0">

                        {/* Título Principal */}
                        <h1 className="text-4xl sm:text-5xl lg:text-7xl font-extrabold mb-4 sm:mb-6 text-gray-900 leading-tight">
                            Defensa <span className="underline decoration-wavy decoration-2 decoration-gray-900">Activa</span> contra Amenazas
                        </h1>

                        {/* Párrafo Principal */}
                        <p className="text-base sm:text-lg lg:text-xl text-gray-700 mb-6 max-w-lg mx-auto md:mx-0">
                            Asegura tus documentos con un análisis ultrarrápido y confiable. Escanea tus archivos localmente, garantizando que tu privacidad y seguridad nunca se vean comprometidas.
                        </p>

                        {/* CTA/Botón Principal */}
                        <div className="flex flex-col sm:flex-row items-center justify-center md:justify-start gap-4 mb-8">
                            {/* Botón de descarga robusto: usa la ruta correcta desde /public y verifica disponibilidad */}
                            <DownloadInstallerButton />
                        </div>

                        {/* Secciones de Login/Registro */}
                        <div className='flex flex-col items-center justify-start md:items-start border-t border-gray-200 pt-6 max-w-lg mx-auto md:mx-0'>
                            <p className="text-sm sm:text-md text-gray-600 mb-4 text-center md:text-left">
                                ¿Listo para comenzar? Si ya tienes una cuenta, inicia sesión para acceder a tu dashboard, o regístrate hoy mismo.
                            </p>
                            {/* CLAVE: W-full en los botones de Login/Register para móvil */}
                            <div className='flex flex-col sm:flex-row items-center justify-center md:justify-start gap-4 w-full'>
                                <button className="w-full sm:w-40 px-4 py-2 bg-white text-blue-700 font-semibold border border-blue-700 rounded-lg hover:bg-blue-50 transition-colors duration-300 ease-in-out cursor-pointer">
                                    <a href="/login">Iniciar Sesión</a>
                                </button>
                                <button className="w-full sm:w-40 px-4 py-2 bg-blue-700 text-white font-semibold rounded-lg hover:bg-sky-800 transition-colors duration-300 ease-in-out cursor-pointer">
                                    <a href="/register">Registrarse</a>
                                </button>
                            </div>
                        </div>

                        <Statistics />

                    </div>

                    {/* Ilustración del Lado Derecho */}
                    <IsometricIllustration />

                </div>

            </main>

            <Footer />

        </div>
    );
}

export default LandingPage;

// Componente separado para manejo más robusto de la descarga
function DownloadInstallerButton() {
    const installerPath = `${import.meta.env.BASE_URL}MalwareScan_Instalador.zip`;

    const handleDownload = async () => {
        try {
            // Verificar que el recurso existe con una petición HEAD (rápida)
            const head = await fetch(installerPath, { method: 'HEAD' });
            if (!head.ok) {
                alert('No se pudo localizar el instalador (HTTP ' + head.status + ').');
                return;
            }
            // Forzar descarga creando un enlace temporal para evitar que el navegador trate el recurso distinto
            const a = document.createElement('a');
            a.href = installerPath;
            a.download = 'MalwareScan_Instalador.zip';
            document.body.appendChild(a);
            a.click();
            a.remove();
        } catch (e) {
            console.error('Error al iniciar la descarga:', e);
            alert('Ocurrió un error al iniciar la descarga. Revisa la consola.');
        }
    };

    return (
        <button
            onClick={handleDownload}
            className="w-full sm:w-auto px-8 py-3 bg-blue-700 text-white font-semibold rounded-lg shadow-lg hover:bg-sky-800 transition-colors duration-300 ease-in-out cursor-pointer"
        >
            Descargar App
        </button>
    );
}