FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY annatar/ annatar/
COPY glorfindel/ glorfindel/

RUN pip install --no-cache-dir -e ".[glorfindel]"

CMD ["glorfindel"]
