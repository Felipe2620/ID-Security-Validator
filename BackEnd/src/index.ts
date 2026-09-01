import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { pool } from './config/db';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Endpoint de prueba de salud de la API y de la Base de Datos
app.get('/api/health', async (req, res) => {
  try {
    // Prueba rápida de consulta a la base de datos
    const dbResult = await pool.query('SELECT NOW()');
    res.json({ 
      status: 'online', 
      message: 'Identity Perimeter Validator Backend operando correctamente',
      tenant: process.env.TENANT_ID,
      db_time: dbResult.rows[0].now
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: 'No se pudo conectar a la base de datos PostgreSQL',
      error: error instanceof Error ? error.message : 'Error desconocido'
    });
  }
});

app.listen(PORT, () => {
  console.log(`⚡️ Servidor Backend escuchando en el puerto ${PORT}`);
});