FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir pymodbus==3.8.6 paho-mqtt==2.1.0 \
    && mkdir -p /opt/metropolis
WORKDIR /opt/metropolis
CMD ["/bin/sh", "-lc", "sleep infinity"]
