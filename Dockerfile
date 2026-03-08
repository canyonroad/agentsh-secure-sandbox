FROM docker.io/cloudflare/sandbox:0.7.13

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends libseccomp2 fuse3 && \
    rm -rf /var/lib/apt/lists/*
