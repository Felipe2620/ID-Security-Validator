import { Request, Response } from 'express';
import { EntraGraphService } from '../services/entraGraphService';

export const verifyTenantConnection = async (req: Request, res: Response) => {
  try {
    const result = await EntraGraphService.testConnection();

    return res.status(200).json({
      status: 'success',
      message: 'Conexión exitosa entre Backend y Tenant de Microsoft Entra ID',
      details: {
        organization: result.organizationName,
        tenant_id: result.tenantId,
      },
    });
  } catch (error: any) {
    console.error('❌ Error autenticando contra Entra ID:', error.message);

    return res.status(500).json({
      status: 'error',
      message: 'No se pudo establecer conexión con el Tenant',
      technical_reason: error.message,
    });
  }
};