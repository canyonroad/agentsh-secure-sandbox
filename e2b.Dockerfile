FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libseccomp2 fuse3 curl ca-certificates bash git sudo && \
    rm -rf /var/lib/apt/lists/*

# Pre-install agentsh v0.18.3
ARG AGENTSH_VERSION=0.18.3
RUN echo "agentsh checksum: 07612c7062e843d0375519c08ac0c590cba99c990c0350ee4bade1fca34f0ddd" && \
    curl -fsSL "https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/agentsh.tar.gz && \
    tar xz -C /tmp/ -f /tmp/agentsh.tar.gz && \
    install -m 0755 /tmp/agentsh /usr/local/bin/agentsh && \
    install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim && \
    install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap && \
    rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap
