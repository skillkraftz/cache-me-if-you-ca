FROM python:3.11-slim
WORKDIR /app
COPY tester/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tester/ .
COPY shared/ ./shared/
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
CMD ["sleep", "infinity"]
