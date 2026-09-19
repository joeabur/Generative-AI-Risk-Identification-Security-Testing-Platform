# Correctly-written container image. The Terraform policies are exercised by
# the vulnerable fixture; this control demonstrates infrastructure written the
# way checkov's bundled policies expect, so a clean run here means the engine
# reports real problems rather than noise.
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --chown=appuser:appuser . /app
USER appuser
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "print('ok')"]
CMD ["python", "/app/src/app.py"]
