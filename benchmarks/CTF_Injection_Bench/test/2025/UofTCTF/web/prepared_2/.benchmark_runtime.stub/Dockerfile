FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY . .
ENV FLAG=uoftctf{5h3_53ll5_534_5h3ll5_by_7h3_C_5h0r3_c9b821c}
EXPOSE 8000
CMD ["python", "app.py"]
