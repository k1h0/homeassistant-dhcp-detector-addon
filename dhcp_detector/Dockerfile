FROM python:3.11-alpine

RUN apk add --no-cache libpcap

WORKDIR /app

COPY dhcp_sniffer.py run.sh ./
RUN chmod +x run.sh

CMD ["/app/run.sh"]
