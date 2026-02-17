# ============================================
# DOCKERFILE FOR KEYORBIT KMS
# Post-Quantum Cryptography Key Management System
# Supports ML-KEM and ML-DSA (NIST FIPS 203/204)
# ============================================

FROM python:3.11-slim

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

# Set working directory
WORKDIR /app

# Install system dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    cmake \
    libssl-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# BUILD LIBOQS WITH POST-QUANTUM ALGORITHMS
# ============================================

WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
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
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. && \
    make -j4 && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf liboqs

# ============================================
# SETUP APPLICATION
# ============================================

WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install liboqs-python

# Copy application code
COPY main.py .
COPY app/ ./app/

# Create necessary directories
RUN mkdir -p /app/logs /app/migrations

# ============================================
# CLEANUP & OPTIMIZATION
# ============================================

RUN apt-get remove -y git build-essential cmake && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/*

# Create non-root user for security (optional but recommended)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# ============================================
# HEALTH CHECK
# ============================================

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port
EXPOSE ${PORT}

# ============================================
# RUN APPLICATION
# ============================================

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 --worker-class sync --timeout 120 --access-logfile - --error-logfile - --log-level info 'main:create_app()'"]