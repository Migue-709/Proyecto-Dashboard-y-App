// GeminiChatBox.jsx

import React, { useState } from 'react';
// Importa tus íconos aquí (ej. @heroicons/react)
import { ChatBubbleLeftRightIcon, MinusIcon } from '@heroicons/react/24/solid'; 

function GeminiChatBox() {
    // Estado para controlar si la ventana del chat está abierta o cerrada/minimizada
    const [isOpen, setIsOpen] = useState(false);

    return (
        // Contenedor principal: siempre fijo en la esquina inferior derecha
        <div className="fixed bottom-4 right-4 z-50">
            
            {/* ---------------------------------------------------- */}
            {/* 1. VENTANA COMPLETA DEL CHAT (Se muestra solo si isOpen es true) */}
            {/* ---------------------------------------------------- */}
            {isOpen && (
                <div className="w-80 h-96 bg-white dark:bg-gray-800 rounded-lg shadow-2xl flex flex-col border border-gray-200 dark:border-gray-700 transition-all duration-300">
                    
                    {/* Header y Botón de Minimizar */}
                    <div className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-gray-700 bg-blue-600 rounded-t-lg">
                        <h2 className="text-md font-semibold text-white">Chat Gemini AI</h2>
                        
                        {/* Botón de Minimizar (cierra la ventana del chat) */}
                        <button 
                            onClick={() => setIsOpen(false)}
                            className="p-1 rounded-full text-white hover:bg-blue-700 transition"
                            title="Minimizar chat"
                        >
                            <MinusIcon className="size-5" />
                        </button>
                    </div>

                    {/* Cuerpo del Chat (Aquí irá la lógica de tu API) */}
                    <div className="flex-grow p-4 overflow-y-auto text-sm text-gray-700 dark:text-gray-300">
                        {/* Aquí va el código de la interfaz del chat: mensajes, input, etc. */}
                        <p className="mb-2">¡Hola! Soy Gemini. ¿En qué puedo ayudarte hoy?</p>
                        {/* Placeholder de contenido */}
                        {/* {Lógica de la API y mensajes} */}
                    </div>

                    {/* Footer / Área de Input */}
                    <div className="p-3 border-t border-gray-200 dark:border-gray-700">
                        <input 
                            type="text" 
                            placeholder="Escribe tu mensaje..." 
                            className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                    </div>
                </div>
            )}

            {/* ---------------------------------------------------- */}
            {/* 2. BOTÓN FLOTANTE (Se muestra solo si isOpen es false) */}
            {/* ---------------------------------------------------- */}
            {!isOpen && (
                <button 
                    onClick={() => setIsOpen(true)}
                    className="size-14 rounded-full bg-blue-600 text-white shadow-xl hover:bg-blue-700 transition-transform duration-300 transform hover:scale-105 flex items-center justify-center focus:outline-none focus:ring-4 focus:ring-blue-300"
                    title="Abrir chat con Gemini"
                >
                    <ChatBubbleLeftRightIcon className="size-7" />
                </button>
            )}
        </div>
    );
}

export default GeminiChatBox;