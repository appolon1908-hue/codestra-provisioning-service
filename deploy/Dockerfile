FROM python:3.12.11-slim-bookworm AS runtime
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --home-dir /nonexistent sipapi
WORKDIR /app
COPY lockfile /app/lockfile
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 \
    && pip install --no-cache-dir --requirement /app/lockfile
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
USER 10001:10001
EXPOSE 8110
ENTRYPOINT ["python", "-m", "uvicorn", "codestra_sip_provisioning.main:app", "--host", "0.0.0.0", "--port", "8110", "--workers", "2"]
