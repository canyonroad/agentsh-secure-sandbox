FROM docker.io/cloudflare/sandbox:0.7.13

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 fuse3 curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Pre-install agentsh v0.16.9
ARG AGENTSH_VERSION=0.16.9
RUN echo "agentsh checksum: 37b7be738291e90957a13653c5bb60b3cbbf9ab5abbc932e00e679a431f9064e" && \
    curl -fsSL "https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/agentsh.tar.gz && \
    tar xz -C /tmp/ -f /tmp/agentsh.tar.gz && \
    install -m 0755 /tmp/agentsh /usr/local/bin/agentsh && \
    install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim && \
    install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap && \
    rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap
