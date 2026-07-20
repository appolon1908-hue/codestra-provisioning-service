FROM python:3.12.11-slim-bookworm AS runtime
RUN useradd --system --uid 10001 --create-home sipapi
WORKDIR /app
COPY lockfile /app/lockfile
RUN pip install --no-cache-dir --requirement /app/lockfile
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
USER 10001:10001
EXPOSE 8110
ENTRYPOINT ["python", "-m", "uvicorn", "codestra_sip_provisioning.main:app", "--host", "127.0.0.1", "--port", "8110"]
