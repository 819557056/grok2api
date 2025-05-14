FROM python:3.9-slim

WORKDIR /app


RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY ./.env /app/
COPY requirements.txt .
COPY app.py .
COPY cf_util.py .
COPY data/ ./data/
COPY templates/ ./templates/


RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5200

CMD ["python", "app.py"]
