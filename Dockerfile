FROM python:3.11-slim-bookworm
RUN pip install scapy requests pymongo
RUN apt update && apt install libpcap-dev tcpdump -y
RUN mkdir /app
WORKDIR /app
ENTRYPOINT ["python", "main.py"]
