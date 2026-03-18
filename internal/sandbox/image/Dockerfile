FROM python:3.12-slim

RUN pip install --no-cache-dir \
    requests \
    httpx \
    aiohttp \
    cryptography \
    pyjwt \
    impacket \
    beautifulsoup4 \
    lxml \
    pwntools \
    scapy \
    paramiko

RUN useradd -m sandbox
WORKDIR /workspace
RUN chown sandbox:sandbox /workspace
USER sandbox

CMD ["sleep", "infinity"]
