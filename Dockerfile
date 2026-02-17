# ============================================
# KEYORBIT KMS - RENDER DEPLOYMENT
# ML-KEM-768 (Kyber768) & ML-DSA-65 (Dilithium3)
# ============================================

FROM python:3.11-slim

# -----------------------------
# Environment Variables
# -----------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=10000

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
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Build liboqs (ML-KEM / ML-DSA)
# -----------------------------
WORKDIR /tmp

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf liboqs

# -----------------------------
# Setup Application
# -----------------------------
WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Copy app code
COPY main.py .

# -----------------------------
# Remove build tools (reduce image size)
# -----------------------------
RUN apt-get purge -y git build-essential cmake && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# -----------------------------
# Non-root user (Security)
# -----------------------------
RUN useradd -m appuser
USER appuser

# -----------------------------
# Expose Render Port
# -----------------------------
EXPOSE ${PORT}

# -----------------------------
# Start Application (Render)
# -----------------------------
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1"]
