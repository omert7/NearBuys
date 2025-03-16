# Dockerfile for API Gateway
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY api-gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY api-gateway/ .

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]