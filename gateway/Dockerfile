FROM python:3.12-slim
# Links the ghcr package to the public repo (github → Packages) so it's discoverable and
# can inherit the repo's visibility. The image carries NO secrets (all config is runtime env).
LABEL org.opencontainers.image.source="https://github.com/joshbilson/caladon"
LABEL org.opencontainers.image.description="Swifty gateway — ciphertext router (T1 attested CVM / T0 self-host)"
WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .
EXPOSE 8088
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
