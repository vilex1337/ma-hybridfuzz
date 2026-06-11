FROM aflplusplus/aflplusplus:latest

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    libtool \
    pkg-config \
    patch \
    bison \
    re2c \
    libxml2-dev \
    libssl-dev \
    libsqlite3-dev \
    libonig-dev \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN git clone https://github.com/php/php-src.git /targets/php && \
    cd /targets/php && git checkout bc39abe8c3c492e29bc5d60ca58442040bbf063b

RUN git clone https://github.com/kkos/oniguruma.git /targets/oniguruma && \
    cd /targets/oniguruma && git checkout 227ec0bd690207812793c09ad70024707c405376

RUN mkdir -p /targets/magma/php
COPY magma/targets/php/patches/ /targets/magma/php/patches/
RUN find /targets/magma/php/patches/setup \
         /targets/magma/php/patches/bugs \
         -name "*.patch" 2>/dev/null | sort | \
    while read patch; do \
        name=$(basename "$patch" .patch); \
        echo "Applying $name"; \
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d /targets/php; \
    done

COPY targets/magma/php/Makefile /targets/magma/php/Makefile

RUN mkdir -p /workspace/{corpus,output,mutators,distance_cache,coverage,logs,memory,instrumented,seed_code} \
    && mkdir -p /opt/mahybridfuzz/src

COPY src/ /opt/mahybridfuzz/src/
COPY configs/ /opt/mahybridfuzz/configs/

WORKDIR /opt/mahybridfuzz
ENV PYTHONPATH=/opt/mahybridfuzz/src

CMD ["python3", "src/orchestrator.py", "-c", "configs/magma/php.yml"]
