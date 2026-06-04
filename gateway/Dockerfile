# Pinned by digest (DH-2): a mutable tag lets the registry serve a different image under the same
# name — the base layer is the broadest supply-chain surface for an attested CVM, so we nail it to
# an immutable content hash. Human tag (python:3.12-slim) kept in this comment for readability.
# Refresh: docker buildx imagetools inspect python:3.12-slim  (use the top-level index Digest).
FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203
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
