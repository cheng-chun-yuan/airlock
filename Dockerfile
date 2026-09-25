FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY packages ./packages
COPY redactor ./redactor
COPY approval ./approval
COPY registry ./registry
COPY audit ./audit
COPY gateway ./gateway
COPY console ./console
COPY demo ./demo
RUN npm ci
ENV NODE_ENV=production PORT=8787
EXPOSE 8787
CMD ["npx", "tsx", "gateway/src/index.ts"]
