FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY server.py okta_auth.py tenant_config.py config_routes.py scopes.py ./

EXPOSE 8000
ENV PORT=8000
ENV HOST=0.0.0.0

CMD ["python", "server.py"]
