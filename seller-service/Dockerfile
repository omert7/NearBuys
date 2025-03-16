FROM python:3.9-slim

WORKDIR /app

# Copy shared requirements
COPY shared/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY seller-service/ .
COPY shared /app/shared

# Add shared to PYTHONPATH
ENV PYTHONPATH=/app

# Expose port
EXPOSE 5005

# Run the application
CMD ["python", "app.py"]