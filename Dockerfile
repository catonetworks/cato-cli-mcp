FROM python:3.12-slim AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./

# Install uv for package management
RUN pip install --no-cache-dir uv

# Install dependencies
RUN uv pip compile pyproject.toml -o requirements.txt && \
    uv pip install --system -r requirements.txt

# Copy the source code
COPY *.py ./


FROM python:3.12-slim

WORKDIR /app

# Create a non-root user to run the application
RUN groupadd -g 1001 catomcp && \
    useradd -m -u 1001 -g catomcp catomcp && \
    chown -R catomcp:catomcp /app

# Install uv for catocli installation at runtime
RUN pip install --no-cache-dir uv
RUN pip install catocli

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app/*.py ./

# Switch to the non-root user
USER catomcp

# Create simple entrypoint script
# server.py handles all catocli configuration
RUN printf "#!/bin/sh\nexec python3 server.py \"$@\"\n" > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Command to run the application
ENTRYPOINT ["/app/entrypoint.sh"]
