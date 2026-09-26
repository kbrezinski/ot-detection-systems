FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_NAME=MET-SENSOR-INTAKE-01 \
    MQTT_HOST=10.20.23.10 \
    MQTT_PORT=1883 \
    MQTT_TOPIC=metropolis/plant/intake/telemetry \
    PUBLISH_INTERVAL=5 \
    SENSOR_TYPE=level \
    SENSOR_VALUE=65.0

RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY devices/field/sensors/mqtt_sensor.py /opt/metropolis/mqtt_sensor.py

CMD ["python", "/opt/metropolis/mqtt_sensor.py"]
