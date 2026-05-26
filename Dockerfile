FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_analyzer_server.py .
COPY templates/ templates/

EXPOSE 8719

CMD ["python", "ai_analyzer_server.py"]
