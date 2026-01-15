# DOCKERFILE GENERATES AN INTERMEDIATE IMAGE (unzipper) THAT CAN BE PRUNED TO FREE UP DISK SPACE

FROM node:20-alpine AS unzipper

WORKDIR /app

# Install the unzip utility package
RUN apk add --no-cache unzip

# copy src folder 
COPY src ./src

# unzip /app/src/assets/images.zip into /app/src/assets
RUN unzip /app/src/assets/images.zip -d /app/src/assets/

# remove zip file
RUN rm /app/src/assets/images.zip


FROM node:20-alpine AS production

WORKDIR /app

COPY package.json package-lock.json challs.json ./

# install server production dependencies
RUN npm install --omit=dev

COPY server.js .

# copies src folder with unzipped files over
COPY --from=unzipper /app/src ./src


EXPOSE 1337
CMD [ "node", "server.js" ]