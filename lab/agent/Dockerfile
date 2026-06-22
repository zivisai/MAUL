FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY services /app/services
COPY main.py /app/main.py

# SERVICE_NAME selects which service's app object main.py exposes
# (issuer | originator | orchestrator | worker | tool).
ENV SERVICE_NAME=issuer
ENV PORT=8443
ENV CERTS_DIR=/certs

CMD ["python", "main.py"]
