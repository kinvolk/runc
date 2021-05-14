ARG GO_VERSION=1.15
ARG BATS_VERSION=v1.2.1

FROM golang:${GO_VERSION}-buster
ARG DEBIAN_FRONTEND=noninteractive

RUN echo 'deb https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_10/ /' > /etc/apt/sources.list.d/criu.list \
    && wget -nv https://download.opensuse.org/repositories/devel:/tools:/criu/Debian_10/Release.key -O- | apt-key add - \
    && dpkg --add-architecture armel \
    && dpkg --add-architecture armhf \
    && dpkg --add-architecture arm64 \
    && dpkg --add-architecture ppc64el \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        astyle \
        build-essential \
        criu \
        crossbuild-essential-arm64 \
        crossbuild-essential-armel \
        crossbuild-essential-armhf \
        crossbuild-essential-ppc64el \
        curl \
        gawk \
        gcc \
        golint \
        gperf \
        iptables \
        jq \
        kmod \
        pkg-config \
        python-minimal \
        sudo \
        uidmap \
    && apt-get clean \
    && rm -rf /var/cache/apt /var/lib/apt/lists/* /etc/apt/sources.list.d/*.list

COPY script/install-libseccomp.sh /
RUN /install-libseccomp.sh

# Add a dummy user for the rootless integration tests. While runC does
# not require an entry in /etc/passwd to operate, one of the tests uses
# `git clone` -- and `git clone` does not allow you to clone a
# repository if the current uid does not have an entry in /etc/passwd.
RUN useradd -u1000 -m -d/home/rootless -s/bin/bash rootless

# install bats
ARG BATS_VERSION
RUN cd /tmp \
    && git clone https://github.com/bats-core/bats-core.git \
    && cd bats-core \
    && git reset --hard "${BATS_VERSION}" \
    && ./install.sh /usr/local \
    && rm -rf /tmp/bats-core

WORKDIR /go/src/github.com/opencontainers/runc
