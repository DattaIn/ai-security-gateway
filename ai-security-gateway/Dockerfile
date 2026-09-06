FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY src ./src

RUN pip install --no-cache-dir -e .

RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "ai_security_gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "src"]
