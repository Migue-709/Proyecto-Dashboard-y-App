import illustration from '../assets/login_register.svg';
const Illustration = () => (
    <div className="flex flex-col items-center justify-center p-6 bg-gray-100 relative h-full">
        <img src={illustration} className="w-screen h-[30vh] -translate-y-6 md:translate-y-0 md:size-full" />
        <div className="absolute bottom-0 md:bottom-4 text-center text-gray-600 px-10 flex flex-col items-center justify-center">
            <svg  className="size-12 text-blue-500 lg:block hidden"  xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" data-slot="icon" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3.8 13.5 14.2 2.2 12 10.6h8.3L9.7 21.8l2.3-8.3H3.7Z"/></svg>
            <h3 className="text-2xl font-bold mb-2">Seguridad de Archivos Local</h3>
            <p className="text-lg lg:block hidden">Analiza y protege tus documentos confidenciales sin subirlos a la nube. Rápido, seguro y privado.</p>
        </div>
    </div>
);
export default Illustration;