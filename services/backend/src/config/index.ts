import dotenv from 'dotenv';

// Esta línea carga las variables de tu archivo .env
dotenv.config(); 

const config = {
  jwt: {
    secret: process.env.JWT_SECRET as string,
  },
  frontend: {
    url: process.env.FRONTEND_URL as string
  }
};

// --- Validación ---
// Si el secreto no está definido, la aplicación se detendrá al iniciar.
// Esto previene errores de seguridad en producción.
if (!config.jwt.secret) {
  throw new Error('FATAL ERROR: JWT_SECRET no está definido en el entorno.');
}
if (!config.frontend.url) {
  throw new Error('FATAL ERROR: FRONTEND_URL no está definida en el entorno.');
}

export default config;