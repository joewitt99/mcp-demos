FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN pip install -r requirements.txt

# Every top-level module server.py imports. Globbed rather than listed
# per-file so adding a module can't silently break the image (tests/
# is a subdirectory and is not copied).
COPY *.py ./

EXPOSE 8000
ENV PORT=8000
ENV HOST=0.0.0.0

CMD ["python", "server.py"]
