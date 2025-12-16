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

# Install git for cloning repositories
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN groupadd -g 1001 catomcp && \
    useradd -m -u 1001 -g catomcp catomcp && \
    chown -R catomcp:catomcp /app

# Install uv for package management
RUN pip install --no-cache-dir uv

# Clone cato-cli repository and install it
RUN git clone https://github.com/catonetworks/cato-cli.git /app/cato-cli && \
    cd /app/cato-cli && \
    sed -i 's/"read_only": false/"read_only": true/' /app/cato-cli/catocli/clisettings.json && \
    pip install -e . && \
    chown -R catomcp:catomcp /app/cato-cli

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
