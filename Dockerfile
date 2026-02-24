FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY daemon.py daemon_worker.py mcp_server.py utils.py ./

ENV DNSPY_DAEMON_PORT=9001
ENV DNSPY_PATH=/opt/dnspy/dnSpy.exe
ENV DNSPY_API_KEY=default-insecure-key-change-me

EXPOSE 9001

CMD ["python3", "daemon.py"]
