FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY subtract.py main.py .

CMD ["kopf", "run", "main.py", "--verbose"]
