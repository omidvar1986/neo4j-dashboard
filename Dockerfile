FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/static /app/logs  # Create logs directory along with static

EXPOSE 8000

RUN chmod +x /app/entrypoint.sh

VOLUME /app/logs  # Add volume for logs

CMD ["/app/entrypoint.sh"]