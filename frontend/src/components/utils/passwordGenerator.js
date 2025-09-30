/**
 * Genera una contraseña segura y aleatoria.
 * @param {number} length - Longitud deseada de la contraseña. Mínimo 12 recomendado.
 * @returns {string} La contraseña generada.
 */
export const generateSecurePassword = (length = 16) => {
    // Define los conjuntos de caracteres
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    // Se excluyen caracteres ambiguos como l, 1, O, 0, i, etc.
    const symbols = '!@#$%^&*()-_+=<>?'; 

    // Combinación de todos los caracteres posibles
    const allChars = upper + lower + numbers + symbols;
    
    let password = '';

    // 1. Asegurar que la contraseña tenga al menos un carácter de cada tipo
    password += upper[Math.floor(Math.random() * upper.length)];
    password += lower[Math.floor(Math.random() * lower.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];

    // 2. Rellenar el resto de la contraseña con caracteres aleatorios
    for (let i = password.length; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * allChars.length);
        password += allChars[randomIndex];
    }
    
    // 3. Mezclar (shuffle) la contraseña para que los primeros caracteres obligatorios no siempre estén al principio
    return password.split('').sort(() => 0.5 - Math.random()).join('');
};