# Usar imagen oficial de Node.js ligera
FROM node:20-alpine

# Crear y definir el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los manifiestos de dependencias
COPY package*.json ./

# Instalar las librerías
RUN npm install

# Copiar el resto del código fuente
COPY . .

# Exponer el puerto del servidor Express
EXPOSE 5000

# Comando de arranque en modo desarrollo
CMD ["npm", "run", "dev"]