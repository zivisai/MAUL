FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir 'httpx>=0.27,<0.28' 'cryptography>=41'
COPY run.py /app/run.py
ENV CERTS_DIR=/certs
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/run.py"]
