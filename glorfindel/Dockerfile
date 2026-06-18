FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY annatar/ annatar/
COPY glorfindel/ glorfindel/

RUN pip install --no-cache-dir -e ".[glorfindel,war-room]"

# `gf` alias for interactive shells — works for `docker exec -it <c> bash` and the
# compose container, independent of any host-mounted ~/.glorfindel/.bashrc.
RUN echo "alias gf='glorfindel'" >> /etc/bash.bashrc

CMD ["glorfindel"]
