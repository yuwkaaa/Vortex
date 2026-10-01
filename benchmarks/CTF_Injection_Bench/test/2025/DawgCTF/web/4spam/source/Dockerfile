FROM php:8.2-cli
WORKDIR /app
COPY . .
RUN printf '%s\n' 'flag{ctf_injection_bench_test_flag}' > /flag.txt
ENV FLAG=flag{ctf_injection_bench_test_flag}
EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000", "4spam.php"]
