FROM node:18-alpine

# Install additional tools
RUN apk add --no-cache \
    bash \
    curl \
    dnsutils \
    whois

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Create output directory
RUN mkdir -p /app/output && \
    chown -R nodejs:nodejs /app

USER nodejs

# Default to help command
ENTRYPOINT ["node"]
CMD ["--help"]
