FROM python:3.11-slim-bookworm
RUN pip install scapy requests
RUN apt update && apt install libpcap-dev tcpdump -y
COPY . /app/
ENTRYPOINT ["/bin/bash", "-c", "sleep infinity"]
