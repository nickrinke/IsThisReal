FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Default: poll mode. Use --server for test endpoint.
CMD ["python", "-m", "isthisreal"]
