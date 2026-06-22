FROM alpine:3.19
RUN apk add --no-cache openssl bash
COPY generate-certs.sh /usr/local/bin/generate-certs.sh
RUN chmod +x /usr/local/bin/generate-certs.sh
ENTRYPOINT ["/usr/local/bin/generate-certs.sh"]
