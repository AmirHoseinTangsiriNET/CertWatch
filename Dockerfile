FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml README.md ./
COPY certwatch ./certwatch
RUN pip install . && rm -rf /src

# run unprivileged; /data is where JSONL output can be written
RUN useradd --system --uid 10001 certwatch && mkdir /data && chown certwatch /data
USER certwatch
WORKDIR /data
VOLUME /data

ENTRYPOINT ["certwatch"]
CMD ["--help"]
