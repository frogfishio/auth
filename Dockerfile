FROM node:10-alpine
COPY service.yaml /app/
COPY build/release /app/
CMD ["node", "node_modules/@frogfish/engine/engine","-c"."service.yaml"]
EXPOSE 8000