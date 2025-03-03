# استفاده از نسخه کم‌حجم پایتون
FROM python:3.11-slim

# تنظیم دایرکتوری کاری
WORKDIR /app

# تنظیم متغیرهای محیطی
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# نصب وابستگی‌های سیستم مورد نیاز
RUN apt-get update && apt-get install -y \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# کپی و نصب وابستگی‌های پروژه
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# کپی کردن کل پروژه به کانتینر
COPY . .
RUN mkdir /app/static

# باز کردن پورت 8000
EXPOSE 8000

RUN chmod +x /app/entrypoint.sh
# استفاده از entrypoint برای اجرای دستورات قبل از اجرای سرور
CMD ["/app/entrypoint.sh"]