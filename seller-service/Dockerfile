FROM python:3.11-slim

WORKDIR /app

# Copy shared utilities first
# COPY ./shared /app/shared

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5004", "app:app"]