FROM python:3.11-alpine

WORKDIR /app

COPY dhcp_sniffer.py run.sh ./
RUN chmod +x run.sh

CMD ["/app/run.sh"]
