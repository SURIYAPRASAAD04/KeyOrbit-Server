# ============================================
# KEYORBIT KMS - PRODUCTION DOCKERFILE
# Post-Quantum Cryptography Key Management System
# ML-KEM-768 (Kyber768) & ML-DSA-65 (Dilithium3)
# ============================================

FROM python:3.11-slim

# -----------------------------
# Environment Variables
# -----------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8000 \
    TZ=Asia/Kolkata \
    FLASK_ENV=production

# -----------------------------
# Install System Dependencies
# -----------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    cmake \
    libssl-dev \
    ca-certificates \
    curl \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Build liboqs (Open Quantum Safe)
# Enables ML-KEM, ML-DSA and other PQC algorithms
# -----------------------------
WORKDIR /tmp

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
        -DOQS_ENABLE_KEM_FRODOKEM=OFF \
        -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
        -DOQS_ENABLE_KEM_BIKE=OFF \
        -DOQS_ENABLE_KEM_HQC=OFF \
        -DOQS_ENABLE_SIG_FALCON=OFF \
        -DOQS_ENABLE_SIG_SPHINCS=OFF \
        -DOQS_ENABLE_SIG_MAYO=OFF \
        -DOQS_ENABLE_SIG_CROSS=OFF \
        -DOQS_ENABLE_SIG_OV=OFF \
        -DOQS_ENABLE_SIG_SNOVA=OFF \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf liboqs

# -----------------------------
# Setup Application Directory
# -----------------------------
WORKDIR /app

# -----------------------------
# Copy requirements first for better caching
# -----------------------------
COPY requirements.txt .

# -----------------------------
# Install Python Dependencies
# -----------------------------
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir liboqs-python gunicorn

# -----------------------------
# Copy Complete Application
# -----------------------------
COPY . .

# -----------------------------
# Create necessary directories
# -----------------------------
RUN mkdir -p /app/logs /app/tmp

# -----------------------------
# Remove build tools to reduce image size
# -----------------------------
RUN apt-get purge -y git build-essential cmake && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

# -----------------------------
# Create non-root user for security
# -----------------------------
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# -----------------------------
# Expose Port
# -----------------------------
EXPOSE ${PORT}

# -----------------------------
# Health Check
# -----------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# -----------------------------
# Start Application with Gunicorn (Production)
# -----------------------------
CMD gunicorn --worker-class sync \
    --workers 4 \
    --threads 2 \
    --timeout 120 \
    --bind 0.0.0.0:${PORT} \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    'main:create_app()'