FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl docker.io \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
      amd64) DOCKER_ARCH="x86_64" ;; \
      arm64) DOCKER_ARCH="aarch64" ;; \
      armhf) DOCKER_ARCH="armel" ;; \
      armv7l) DOCKER_ARCH="armel" ;; \
      ppc64el) DOCKER_ARCH="ppc64le" ;; \
      s390x) DOCKER_ARCH="s390x" ;; \
      *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
    esac \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-24.0.7.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/* /usr/local/bin/ \
    && chmod +x /usr/local/bin/docker \
    && docker --version \
    && rm -rf /tmp/docker.tgz /tmp/docker \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir qlever==0.5.47

COPY . .
RUN chmod +x scripts/docker-entrypoint-qlever.sh

CMD ["sleep", "infinity"]
