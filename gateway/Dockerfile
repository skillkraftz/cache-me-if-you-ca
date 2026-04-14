FROM python:3.11-slim
WORKDIR /app
COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gateway/ .
COPY shared/ ./shared/
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
CMD ["python", "serve.py"]
