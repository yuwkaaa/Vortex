FROM ubuntu:24.04

RUN apt-get update && \
    apt-get -y install python3 python3-pip libicu-dev python3-icu pkg-config \
                       imagemagick openssl gcc libssl-dev && \
    python3 -m pip config set global.break-system-packages true && \
    pip install --no-cache-dir playwright && \
    playwright install-deps && \
    apt-get clean

ARG APP_USER=app
ARG APP_UID=10001
ARG APP_GID=10001

ARG FLAG_USER=flaguser
ARG FLAG_UID=10002
ARG FLAG_GID=10002

RUN groupadd --gid ${APP_GID} ${APP_USER} && \
    useradd --uid ${APP_UID} --gid ${APP_GID} -s /bin/bash ${APP_USER} && \
    mkdir -p /home/app && chown ${APP_UID}:${APP_GID} /home/app && \
    groupadd --gid ${FLAG_GID} ${FLAG_USER} && \
    useradd --uid ${FLAG_UID} --gid ${FLAG_GID} -s /bin/bash ${FLAG_USER} && \
    mkdir -p /home/${FLAG_USER} && chown ${FLAG_UID}:${FLAG_GID} /home/${FLAG_USER} && \
    mkdir -p /home/shared && chmod 0755 /home/shared



ENV FLAG="MIPT{fake_flag}"
ENV SECRET_KEY="SECRET_KEY{fake_secret}"
ENV ADMIN_PASSWORD="SECRET_KEY{fake_secret}"

WORKDIR /home/app

COPY requirements.txt /home/app/
USER root
RUN pip install --no-cache-dir -r /home/app/requirements.txt

USER ${APP_UID}:${APP_GID}
RUN playwright install chromium
USER root

# ── Build trusted-executor ────────────────────────────────────────────────────
COPY trusted-executor.c /tmp/build/trusted-executor.c
COPY compress.sh /tmp/build/compress.sh

RUN cd /tmp/build && \
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem && \
    openssl pkey -in private.pem -pubout -out public.pem && \
    printf 'const char *PUBLIC_KEY_PEM = "' > public.pem.c && \
    sed 's/$/\\n/' public.pem | tr -d '\n' >> public.pem.c && \
    printf '";\n' >> public.pem.c && \
    gcc -Wall -Wextra -Werror -o trusted-executor trusted-executor.c public.pem.c -lcrypto && \
    openssl dgst -sha256 -sign private.pem -out compress.sh.sig compress.sh && \
    cp trusted-executor /home/shared/trusted-executor && \
    cp compress.sh /home/shared/compress.sh && \
    cp compress.sh.sig /home/shared/compress.sh.sig && \
    chown ${FLAG_UID}:${FLAG_GID} /home/shared/trusted-executor && \
    chmod 4755 /home/shared/trusted-executor && \
    chown ${FLAG_UID}:${FLAG_GID} /home/shared/compress.sh /home/shared/compress.sh.sig && \
    chmod 0755 /home/shared/compress.sh && \
    chmod 0644 /home/shared/compress.sh.sig && \
    rm -rf /tmp/build

# ── Copy app ──────────────────────────────────────────────────────────────────
COPY app.py /home/app/
COPY templates/ /home/app/templates/
COPY static/ /home/app/static/
COPY entrypoint.sh /home/app/entrypoint.sh
RUN chmod +x /home/app/entrypoint.sh

EXPOSE 3000

CMD ["/home/app/entrypoint.sh"]
