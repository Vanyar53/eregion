FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY annatar/ annatar/
COPY glorfindel/ glorfindel/
COPY scenarios/ scenarios/
COPY scripts/ scripts/

RUN pip install --no-cache-dir -e .

CMD ["annatar"]
