FROM python:3.11-alpine

RUN apk add --no-cache libpcap

# Install paho-mqtt for MQTT Discovery and state publishing
RUN pip install --no-cache-dir paho-mqtt

WORKDIR /app

COPY dhcp_sniffer.py run.sh ./
RUN chmod +x run.sh

CMD ["/app/run.sh"]
