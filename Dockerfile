# SentryIP - Lightweight Multi-Stage Container Image
FROM python:3.11-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev

COPY pyproject.toml .
COPY sentryip ./sentryip
COPY README.md .

RUN pip install --no-cache-dir --prefix=/install .

# Final Runner Image
FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /install /usr/local
COPY sentryip ./sentryip
COPY sample_ips.txt .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["sentryip"]
CMD ["--auto"]
