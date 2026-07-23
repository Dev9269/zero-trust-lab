FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 9191
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; exit(0) if urllib.request.urlopen('http://localhost:9191/healthz').status == 200 else exit(1)"
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:9191", "app:app"]
