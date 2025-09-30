// Expresión regular estándar para validar email
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_REGEX = /^[A-ZÀ-Ÿ][a-zà-ÿ]+$/u;
const NAME_PASSWORD_MAX = 20
const EMAIL_MAX = 30
const NAME_MIN = 3
const EMAIL_MIN = 6
const PASSWORD_MIN = 8
/**
 * Valida que el campo  cumpla con ciertos criterios.
 * @param {string} target  - El campo ingresado por el usuario.
 * @returns {string | null} Mensaje de error o null si es válido.
 */
export const validateName = (name) => {
    if (!name || name.trim() === '')
        return "El campus nombre es obligatorio.";
    if (name.length < NAME_MIN) 
        return `El campus nombre debe tener al menos ${NAME_MIN} caracteres.`;
    if(name.length>NAME_PASSWORD_MAX)
        return `El campus nombre permite máximo ${NAME_PASSWORD_MAX} caracteres.`;
    if (!NAME_REGEX.test(name))
        return "El formato del campus nombre no es válido";
    return null;
};
export const validateEmail = (email) => {
    if (!email || email.trim() === '')
        return "El campus email es obligatorio.";
    if(email.length<EMAIL_MIN)
        return `El campus email debe tener al menos ${EMAIL_MIN} caracteres.`;
    if(email.length>EMAIL_MAX)
        return `El campus correo permite máximo ${EMAIL_MAX} caracteres.`;
    if (!EMAIL_REGEX.test(email))
        return "El formato del campus email no es válido.";
    return null;
};

export const validatePassword = (password) => {
    if (!password || password.trim() === '')
        return "El campus contraseña es obligatoria.";
    if (password.length < PASSWORD_MIN) 
        return `El campus contraseña debe tener al menos ${PASSWORD_MIN} caracteres.`;
    if (password.length > NAME_PASSWORD_MAX) 
        return `El campus contraseña permite máximo ${NAME_PASSWORD_MAX} caracteres.`;
    if (!/[A-Z]/.test(password))
        return "El campus contraseña  debe incluir al menos una letra mayúscula.";
    if (!/[a-z]/.test(password))
        return "El campus contraseña  debe incluir al menos una letra minúscula.";
    if (!/[0-9]/.test(password))
        return "El campus contraseña  debe incluir al menos un número.";
    return null;
};
/**
 * Valida un objeto completo de datos de registro.
 * @param {object} data - {name, email, password}
 * @returns {object} Un objeto de errores donde cada clave tiene un mensaje de error o null.
 */
export const validateRegistrationForm = (name ,email, password) => {
    const errors = {};
    errors.name = validateName(name);
    errors.email = validateEmail(email);
    errors.password = validatePassword(password);
    // Filtrar sólo errores reales
    const realErrors = Object.keys(errors).reduce((acc, key) => {
        if (errors[key]) acc[key] = errors[key];
        return acc;
    }, {});
    // IMPORTANTE: retornar null si no hay errores para que el submit continúe
    return Object.keys(realErrors).length === 0 ? null : realErrors;
};
export const validateSignInForm = ( email, password) => {
    const errors = {};
    errors.email = validateEmail(email);
    errors.password = validatePassword(password);
    // Filtrar sólo errores reales
    const realErrors = Object.keys(errors).reduce((acc, key) => {
        if (errors[key]) acc[key] = errors[key];
        return acc;
    }, {});
    // IMPORTANTE: retornar null si no hay errores para que el submit continúe
    return Object.keys(realErrors).length === 0 ? null : realErrors;
};