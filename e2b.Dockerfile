FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libseccomp2 fuse3 curl ca-certificates bash git sudo && \
    rm -rf /var/lib/apt/lists/*

# Pre-install agentsh v0.16.9
ARG AGENTSH_VERSION=0.16.9
RUN echo "agentsh checksum: 6928a92ab040ca014be21f08f6d5df177d66685c85d62a82758511a7312b2795" && \
    curl -fsSL "https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/agentsh.tar.gz && \
    tar xz -C /tmp/ -f /tmp/agentsh.tar.gz && \
    install -m 0755 /tmp/agentsh /usr/local/bin/agentsh && \
    install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim && \
    install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap && \
    rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap
