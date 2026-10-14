FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/

# Ex?cution sans droits root
RUN useradd --create-home agent
USER agent

# La cl? GROQ_API_KEY est fournie ? l'ex?cution, jamais dans l'image
ENTRYPOINT ["python", "src/agent_llm.py"]
