FROM busybox:latest

RUN mkdir /app
WORKDIR /app
COPY . .
RUN ls -la

CMD ["/bin/sh", "-c", "ls -la "] 