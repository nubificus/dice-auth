FROM harbor.nbfc.io/proxy_cache/library/alpine:latest

RUN apk add --no-cache \
    build-base \
    openssl-dev \
    make \
    hiredis-dev

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

RUN make dice_auth

CMD ["/app/auth"]
