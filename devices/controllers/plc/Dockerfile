FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_NAME=MET-PLC-INTAKE-01 \
    DEVICE_ROLE=PLC \
    MODBUS_HOST=0.0.0.0 \
    MODBUS_PORT=502

RUN pip install --no-cache-dir pymodbus==3.8.6
COPY devices/controllers/plc/modbus_controller.py /opt/metropolis/modbus_controller.py

EXPOSE 502/tcp
CMD ["python", "/opt/metropolis/modbus_controller.py"]
