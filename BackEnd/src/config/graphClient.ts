import { ClientSecretCredential } from '@azure/identity';
import { Client } from '@microsoft/microsoft-graph-client';
import { TokenCredentialAuthenticationProvider } from '@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials';
import dotenv from 'dotenv';

dotenv.config();

const tenantId = process.env.TENANT_ID!;
const clientId = process.env.CLIENT_ID!;
const clientSecret = process.env.CLIENT_SECRET!;

if (!tenantId || !clientId || !clientSecret) {
  throw new Error('Faltan variables de entorno para la conexión con Entra ID/Graph API.');
}

// Credencial en memoria con el flujo OAuth 2.0 Client Credentials
const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

// Proveedor de autenticación nativo para la Microsoft Graph API
const authProvider = new TokenCredentialAuthenticationProvider(credential, {
  scopes: ['https://graph.microsoft.com/.default'],
});

// Instancia única exportada (Singleton Pattern)
export const graphClient = Client.initWithMiddleware({ authProvider });