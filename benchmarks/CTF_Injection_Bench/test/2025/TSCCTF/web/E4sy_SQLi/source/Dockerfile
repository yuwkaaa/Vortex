FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY . .
ENV FLAG=flag{ctf_injection_bench_test_flag}
EXPOSE 8000
CMD ["python", "benchmark_app.py"]
