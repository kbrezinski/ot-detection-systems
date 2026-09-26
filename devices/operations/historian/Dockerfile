FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_NAME=MET-HISTORIAN-01 \
    MQTT_HOST=10.20.23.10 \
    MQTT_PORT=1883 \
    MQTT_TOPIC=metropolis/#

RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY devices/operations/historian/historian_collector.py /opt/metropolis/historian_collector.py

CMD ["python", "/opt/metropolis/historian_collector.py"]
