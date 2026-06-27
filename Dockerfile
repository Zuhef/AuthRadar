# AuthRadar container image.
# Browser-based checks (JWT in web storage) require a Playwright browser binary,
# which is NOT included to keep the image small. To enable them, extend this
# image and run `playwright install --with-deps chromium`.
FROM python:3.12-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy only what is needed to build/install the package.
COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY authradar ./authradar

RUN python -m pip install --upgrade pip \
    && python -m pip install .

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 authradar
USER authradar

ENTRYPOINT ["authradar"]
CMD ["--help"]
