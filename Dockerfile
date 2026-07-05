FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# AgentCore Runtime expects port 8080
EXPOSE 8080

# Set the default region (override via AgentCore config or env)
ENV AWS_REGION=us-east-1

# Entrypoint for AgentCore Runtime
CMD ["python", "main.py"]
