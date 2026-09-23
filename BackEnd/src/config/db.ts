import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// Configuración del Pool de conexiones a PostgreSQL usando los datos del Docker Compose
export const pool = new Pool({
  host: process.env.DB_HOST || 'postgres_db',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT) || 5432,
});

pool.on('connect', () => {
  console.log('📦 Conectado exitosamente a la base de datos PostgreSQL');
});