import { useRef, useEffect } from "react";
import gsap from 'gsap';

function Message({ msg, onComplete }) {
  const msgRef = useRef(null);

  useEffect(() => {
    const element = msgRef.current;
    if (!element || !msg) {
        // Si no hay elemento o no hay mensaje, nos aseguramos de que esté oculto
        if (element) {
             gsap.set(element, { x: '110%', opacity: 0, display: 'none' });
        }
        return;
    }

    // Limpiamos cualquier animación que pueda estar corriendo
    gsap.killTweensOf(element);

    // 1. Inicialización: Colocamos el elemento fuera de la pantalla a la derecha
    // y lo hacemos visible para GSAP.
    gsap.set(element, { x: '110%', opacity: 0, display: 'grid' });

    // 2. Creamos la línea de tiempo para secuenciar los movimientos
    const tl = gsap.timeline();

    // -- FASE 1: ENTRADA (Derecha a su posición) --
    tl.to(element, {
      x: '0%', // Posición final (en el borde derecho)
      opacity: 1,
      duration: 0.5,
      ease: 'power2.out'
    })

    // -- FASE 2: PAUSA (Se mantiene visible) --
    // Usamos un .to con una duración muy corta y un gran delay para pausar
    .to(element, {
      duration: 0.1, 
      delay: 2.5 // Pausa de 2.5 segundos en la pantalla
    })

    // -- FASE 3: SALIDA (De su posición hacia la derecha y desaparece) --
    .to(element, {
      x: '110%', // Vuelve a salir por la derecha
      opacity: 0,
      duration: 0.5,
      ease: 'power2.in',
      onComplete: () => {
        // 3. Finalización: Ocultamos el elemento por completo
        gsap.set(element, { display: 'none' });
        
        // 4. Llamamos al callback para que el componente padre
        // pueda resetear la variable `msg` a una cadena vacía o null.
        if (onComplete) {
          onComplete();
        }
      }
    });

    return () => tl.kill();

  }, [onComplete]); // Dependencia en msg y onComplete

  return (
    <div 
      ref={msgRef} 
      // Usá border-b-green-500 para éxito y cambiá la clase dinámicamente si es un error
      className="bg-slate-300/40 dark:bg-slate-800/40 dark:text-white shadow-2xl fixed bottom-4 right-4 p-4 rounded-xl min-w-24 min-h-6 max-w-sm grid place-content-center border-t-2 border-t-stone-900"
    >
      <span className="text-sm text-justify">{msg}</span>
    </div>
  )
}

export default Message;