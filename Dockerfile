FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lab/ ./lab/
COPY attack/ ./attack/
COPY policy/ ./policy/
COPY scripts/ ./scripts/

ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app

# Overridden per service in docker-compose.yml
CMD ["python", "-m", "lab.serve", "idp"]
