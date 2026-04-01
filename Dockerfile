# PQ Agile Wrapper — Shadow Proxy
# Containerised Post-Quantum Security Sidecar
#
# Build:  docker build -t pq-shadow-proxy .
# Run:    docker run -p 8443:8443 pq-shadow-proxy

FROM python:3.12-slim AS base

# Install system dependencies for liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && mkdir build && cd build \
    && cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        .. \
    && ninja install \
    && rm -rf /tmp/liboqs

# Set library path
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install liboqs-python
RUN pip install --no-cache-dir oqs

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY demo/ ./demo/

# Create data directories
RUN mkdir -p /app/data/keys /app/logs

# Expose the proxy port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',8443)); s.close()" || exit 1

# Run the Shadow Proxy
ENTRYPOINT ["python", "-m", "src"]
CMD ["--config", "config/default.yaml"]
