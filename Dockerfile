FROM docker.io/cloudflare/sandbox:0.7.13

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 fuse3 curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Pre-install agentsh v0.18.0
ARG AGENTSH_VERSION=0.18.0
RUN echo "agentsh checksum: fb0bbcce29a940ec1e3a0491f253bfc0837884a39d6b3b507f36c4f2d10a8934" && \
    curl -fsSL "https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/agentsh.tar.gz && \
    tar xz -C /tmp/ -f /tmp/agentsh.tar.gz && \
    install -m 0755 /tmp/agentsh /usr/local/bin/agentsh && \
    install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim && \
    install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap && \
    rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap
