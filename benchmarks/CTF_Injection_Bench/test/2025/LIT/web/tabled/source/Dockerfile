FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends socat gcc g++ make sqlite3 curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask gunicorn requests jinja2 werkzeug pyjwt itsdangerous markupsafe markdown pyyaml beautifulsoup4 lxml
COPY . .
ENV FLAG=flag{ctf_injection_bench_test_flag}
EXPOSE 8000
CMD ["python", ".benchmark/run_python_web.py", "main.py", "8000"]
