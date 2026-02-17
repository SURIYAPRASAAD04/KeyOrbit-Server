# ==========================================
# KEYORBIT KMS - PRODUCTION DOCKERFILE
# Flask + Gunicorn + liboqs (Kyber + Dilithium)
# ==========================================

FROM python:3.11-slim

# ------------------------------------------
# System Dependencies
# ------------------------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------
# Install liboqs (ONLY Kyber + Dilithium)
# ------------------------------------------
WORKDIR /opt

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        \
        -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
        -DOQS_ENABLE_KEM_FRODOKEM=OFF \
        -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
        -DOQS_ENABLE_KEM_BIKE=OFF \
        -DOQS_ENABLE_KEM_HQC=OFF \
        \
        -DOQS_ENABLE_SIG_FALCON=OFF \
        -DOQS_ENABLE_SIG_SPHINCS=OFF \
        -DOQS_ENABLE_SIG_MAYO=OFF \
        -DOQS_ENABLE_SIG_CROSS=OFF \
        -DOQS_ENABLE_SIG_OV=OFF \
        -DOQS_ENABLE_SIG_SNOVA=OFF \
        \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. \
    && cmake --build . --parallel \
    && cmake --install .

ENV LD_LIBRARY_PATH=/usr/local/lib

# ------------------------------------------
# Application Setup
# ------------------------------------------
WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# ------------------------------------------
# Expose Port
# ------------------------------------------
EXPOSE 8000

# ------------------------------------------
# Start Gunicorn
# ------------------------------------------
CMD ["gunicorn", "main:create_app()", "--bind", "0.0.0.0:8000", "--workers", "2"]
