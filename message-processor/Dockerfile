FROM python:3.9-slim

WORKDIR /app

# Copy requirements
COPY message-processor/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY message-processor/ .
COPY shared /app/shared

# Add shared to PYTHONPATH
ENV PYTHONPATH=/app

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "app.py"] 