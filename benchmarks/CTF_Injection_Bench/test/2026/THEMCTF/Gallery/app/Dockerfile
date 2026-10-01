FROM python:3.14.0b2-alpine

WORKDIR /app

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

RUN apk add --no-cache attr

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY ./src .

RUN addgroup -S app-user -g 1000 && \
    adduser -S -D -H -G app-user -u 1000 app-user

RUN echo -n 'THEM?!CTF{FakeFlag_LMAO}' > /flag.txt && \
    chmod 444 /flag.txt && \
    chown root:root /flag.txt

RUN mkdir -p /app/uploads /app/reports && \
    chown -R app-user:app-user /app && \
    chmod 755 /app && \
    chmod 755 /app/uploads /app/reports && \
    chmod 755 /tmp

RUN chmod 1733 /tmp

RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true


USER app-user

EXPOSE 5000

CMD ["gunicorn", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]   