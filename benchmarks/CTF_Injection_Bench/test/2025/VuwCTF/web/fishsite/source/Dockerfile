FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY . .
RUN python .benchmark_init_db.py
ENV FLAG=flag{ctf_injection_bench_test_flag}
EXPOSE 9995
CMD ["python", "fishsite.py"]
