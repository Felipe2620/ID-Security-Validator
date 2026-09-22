import { graphClient } from '../config/graphClient';

export class EntraGraphService {
  /**
   * Prueba simple de conectividad y autenticación con el Tenant de Entra ID
   */
  static async testConnection() {
    const response = await graphClient
      .api('/organization')
      .select('id,displayName')
      .get();

    return {
      connected: true,
      tenantId: response.value[0]?.id,
      organizationName: response.value[0]?.displayName,
    };
  }
}