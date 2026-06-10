# Use a slim Python image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ogcproxy.py .

# Expose port
EXPOSE 8000

ENV WORKERS=2
ENV TIMEOUT=30
ENV REDIS_URL=redis://redis:6379/0

# Run with Gunicorn + Uvicorn worker
CMD ["sh", "-c", "gunicorn ogcproxy:app -k uvicorn.workers.UvicornWorker -w ${WORKERS} -b 0.0.0.0:8000 --timeout ${TIMEOUT}"]
