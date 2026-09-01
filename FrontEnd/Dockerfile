# Usar imagen oficial de Node.js ligera
FROM node:20-alpine

# Crear y definir el directorio de trabajo
WORKDIR /app

# Copiar los manifiestos de dependencias
COPY package*.json ./

# Instalar las librerías de React
RUN npm install

# Copiar el resto del código fuente de React
COPY . .

# Exponer el puerto de Vite
EXPOSE 3000

# Comando de arranque del frontend en desarrollo
CMD ["npm", "run", "dev"]