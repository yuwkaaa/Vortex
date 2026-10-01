FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends bash iputils-ping gcc libc6-dev && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN gcc readflag.c -o readflag && chmod 4755 readflag

RUN chown -R ctf:ctf /app

USER ctf

EXPOSE 5030

CMD ["python", "app.py"]
