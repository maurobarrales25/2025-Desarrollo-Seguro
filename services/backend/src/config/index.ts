import dotenv from 'dotenv';

// Esta línea carga las variables de tu archivo .env
dotenv.config(); 

const config = {
  jwt: {
    secret: process.env.JWT_SECRET,
  }
};

// --- Validación ---
// Si el secreto no está definido, la aplicación se detendrá al iniciar.
// Esto previene errores de seguridad en producción.
if (!config.jwt.secret) {
  throw new Error('FATAL ERROR: JWT_SECRET no está definido en el entorno.');
}

export default config;