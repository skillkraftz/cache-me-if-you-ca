FROM python:3.11-slim
WORKDIR /app
COPY internal-admin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY internal-admin/ .
COPY shared/ ./shared/
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
CMD ["python", "app.py"]
