FROM docker.io/cloudflare/sandbox:0.7.13

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 fuse3 curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Pre-install agentsh v0.20.1
ARG AGENTSH_VERSION=0.20.1
RUN echo "agentsh checksum: 7e8d49c6774e1945c681525c7f3b5e1506043c6ce50e7412c7708f99661418ed" && \
    curl -fsSL "https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/agentsh.tar.gz && \
    tar xz -C /tmp/ -f /tmp/agentsh.tar.gz && \
    install -m 0755 /tmp/agentsh /usr/local/bin/agentsh && \
    install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim && \
    install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap && \
    rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap
