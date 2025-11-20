FROM ubuntu:24.04

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    build-essential \
    curl \
    wget \
    git \
    unzip \
    zip \
    cmake \
    pkg-config \
    perl \
    nasm \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN mkdir -p /app/certs

# Копируем PFX в контейнер
COPY certs/200ok.pfx /app/certs/200ok.pfx

# Сборка OpenSSL 3.6.0 с поддержкой GOST и legacy алгоритмов
RUN wget https://www.openssl.org/source/openssl-3.6.0.tar.gz \
    && tar xzf openssl-3.6.0.tar.gz \
    && cd openssl-3.6.0 \
    && ./Configure linux-x86_64 \
        --prefix=/usr/local/openssl-3.6 \
        --openssldir=/usr/local/openssl-3.6 \
        enable-ec_nistp_64_gcc_128 enable-gost enable-legacy \
    && make -j$(nproc) \
    && make install

# Регистрируем библиотеки для ldconfig + обновляем кеш
RUN echo "/usr/local/openssl-3.6/lib" > /etc/ld.so.conf.d/openssl-3.6.conf \
    && echo "/usr/local/openssl-3.6/lib64" >> /etc/ld.so.conf.d/openssl-3.6.conf \
    && ldconfig

# Переменные окружения для OpenSSL
ENV OPENSSL_ROOT_DIR=/usr/local/openssl-3.6
ENV PATH="/usr/local/openssl-3.6/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/openssl-3.6/lib:/usr/local/openssl-3.6/lib64:${LD_LIBRARY_PATH}"

# Переменные окружения для Java KeyStore
ENV PFX_PATH=/app/certs/200ok.pfx
ENV PFX_PASS=9567632a

WORKDIR /app
COPY . /app

# Сборка проекта
RUN chmod +x ./gradlew
RUN ./gradlew build -x test --no-daemon
RUN cp build/libs/api-security-analyzer-*-SNAPSHOT.jar /app/api-security-analyzer.jar

EXPOSE 8080

# Запуск приложения с передачей PFX напрямую как KeyStore
CMD ["java", "-Djavax.net.ssl.keyStore=/app/certs/200ok.pfx", "-Djavax.net.ssl.keyStorePassword=9567632a", "-Djavax.net.ssl.keyStoreType=PKCS12", "-jar", "/app/api-security-analyzer.jar"]
