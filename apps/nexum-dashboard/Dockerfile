# OPS: standalone synthetic GUI prototype, not the production client.
FROM alpine:3.23
RUN apk add --no-cache python3 && adduser -D -u 10001 nexum
WORKDIR /app
COPY server.py ./
COPY public ./public
USER 10001:10001
EXPOSE 8787
CMD ["python3", "-B", "server.py", "--bind", "0.0.0.0", "--port", "8787"]
