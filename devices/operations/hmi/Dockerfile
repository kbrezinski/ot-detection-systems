FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_NAME=MET-HMI-INTAKE-01 \
    MQTT_HOST=10.20.23.10 \
    MQTT_PORT=1883 \
    MQTT_TOPIC=metropolis/plant/intake/command \
    PUBLISH_INTERVAL=30 \
    SETPOINT=65.0

RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY devices/operations/hmi/hmi_simulator.py /opt/metropolis/hmi_simulator.py

CMD ["python", "/opt/metropolis/hmi_simulator.py"]
