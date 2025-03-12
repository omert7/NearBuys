FROM python:3.11-slim

WORKDIR /app

# Copy shared utilities first
# COPY ./shared /app/shared

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5003

# Run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "app:app"]
