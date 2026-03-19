# Usa una imagen base de Node.js. Elige una versión LTS (Long Term Support).
FROM node:18-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /usr/src/app

# Copia los archivos de definición de dependencias
COPY package.json package-lock.json* ./

# Instala las dependencias del proyecto
# Usamos --only=production para no instalar dependencias de desarrollo como 'nodemon'
RUN npm install --only=production

# Copia el resto de los archivos de tu aplicación
COPY . .

# Expone el puerto en el que la aplicación se ejecutará (Coolify usará el valor de la variable de entorno PORT)
EXPOSE 3000

# El comando para iniciar la aplicación
CMD [ "node", "backend.js" ]
