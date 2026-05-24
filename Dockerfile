FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY ml/ ./ml/

RUN python ml/train.py

CMD ["python", "-m", "agent.agent"]