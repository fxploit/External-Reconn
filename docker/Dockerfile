# recon-harness 실행 이미지
#
# 컨테이너는 "수집·실행"만 담당하고, 검증(해시·인용 재계산)은 호스트 게이트가 수행한다.
# 베이스 이미지도 digest로 고정해 재현성을 확보한다.
#
# 빌드:
#   docker build -t recon-harness ./docker
#   docker images --no-trunc --format '{{.ID}}' recon-harness   # -> sha256 digest 확보
#   docker/compose.yaml 의 image: recon-harness@sha256:<digest> 에 고정

# mcr.microsoft.com/playwright/python (chromium 포함) — base digest 고정
FROM mcr.microsoft.com/playwright/python:v1.53.0-noble@sha256:648e2d7cb4136587116ba42bc4b1f7d23a6776f3237d5c27995f338c1e57f73f

WORKDIR /work
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 능동 정찰 도구 (포트/서비스 스캔, vhost/디렉터리 열거)
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nmap \
        gobuster \
        curl \
        dnsutils \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# 파이썬 의존성 — playwright 패키지는 베이스 이미지에 브라우저(chromium-1179)가 깔려 있으므로
# 버전을 맞춰 설치하면 재다운로드 없이 그 브라우저를 그대로 쓴다.
RUN pip install --no-cache-dir \
        playwright==1.53.0 \
        jsbeautifier \
        wafw00f==2.4.2

# cariddi (자산 추출 보조 — T15). 릴리스 바이너리를 버전 고정으로 받고 sha256 검증.
# 출처: https://github.com/edoardottt/cariddi (Apache-2.0)
RUN set -eux; \
    cd /tmp; \
    curl -fsSLO https://github.com/edoardottt/cariddi/releases/download/v1.4.6/cariddi_1.4.6_linux_amd64.zip; \
    echo "b8268f76bd6c4eda79615791b26676ec392a3eb2a73568a29f6e5af297ff5696  cariddi_1.4.6_linux_amd64.zip" | sha256sum -c -; \
    unzip -o cariddi_1.4.6_linux_amd64.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/cariddi; \
    rm -f /tmp/cariddi_*; \
    cariddi -version 2>&1 | head -1 || true

# 하네스 코드를 이미지에 복사(컬렉션 결과는 targets/ 마운트 볼륨에 저장)
COPY scripts/ /work/scripts/
COPY harness/ /work/harness/
COPY package.json /work/package.json

# 장수(long-lived) 컨테이너 — up -d 후 exec 로 명령을 투입한다.
CMD ["sleep", "infinity"]
