FROM buildpack-deps:bullseye

# Original image derived from tiangolo/nginx-rtmp
# by Sebastian Ramirez <tiangolo@gmail.com>
LABEL maintainer="Sunny Xu <therealsunnyxu@gmail.com>"

# Versions of Nginx and nginx-rtmp-module to use
ENV NGINX_VERSION nginx-1.23.2
ENV NGINX_RTMP_MODULE_VERSION 1.2.2

# Install dependencies for nginx, ffmpeg, and python
RUN apt-get update && \
    apt-get install -y autoconf \
    automake \
    build-essential \
    bzip2 \
    ca-certificates \
    cmake \
    default-libmysqlclient-dev \
    dpkg-dev \
    file \
    g++ \
    gcc \
    git \
    git-core \
    imagemagick \
    libass-dev \
    libbz2-dev \
    libc6-dev \
    libcurl4-openssl-dev \
    libdb-dev \
    libevent-dev \
    libffi-dev \
    libfreetype6-dev \
    libgdbm-dev \
    libglib2.0-dev \
    libgmp-dev \
    libgnutls28-dev \
    libjpeg-dev \
    libkrb5-dev \
    liblzma-dev \
    libmagickcore-dev \
    libmagickwand-dev \
    libmaxminddb-dev \
    libmp3lame-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libpng-dev \
    libpq-dev \
    libreadline-dev \
    libsdl2-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libva-dev \
    libvdpau-dev \
    libvorbis-dev \
    libwebp-dev \
    libxcb-shm0-dev \
    libxcb-xfixes0-dev \
    libxcb1-dev \
    libxml2-dev \
    libxslt-dev \
    libyaml-dev \
    make \
    meson \
    nasm \
    ninja-build \
    openssl \
    patch \
    pkg-config \
    python3 \
    python3-pip \
    texinfo \
    unzip \
    wget \
    xz-utils \
    yasm \
    zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Download and decompress ffmpeg
# Put the bin in /usr/bin to be consistent with nginx
RUN mkdir -p /tmp/build/ffmpeg_sources && \
    cd /tmp/build/ffmpeg_sources && \
    wget -O ffmpeg-snapshot.tar.bz2 https://ffmpeg.org/releases/ffmpeg-snapshot.tar.bz2 && \
    tar xjvf ffmpeg-snapshot.tar.bz2

RUN cd /tmp/build/ffmpeg_sources/ffmpeg && \
    PATH="/usr/bin:$PATH" PKG_CONFIG_PATH="/tmp/build/ffmpeg_build/lib/pkgconfig" ./configure \
    --prefix="/tmp/build/ffmpeg_build" \
    --pkg-config-flags="--static" \
    --extra-cflags="-I/tmp/build/ffmpeg_build/include" \
    --extra-ldflags="-L/tmp/build/ffmpeg_build/lib" \
    --extra-libs="-lpthread -lm" \
    --ld="g++" \
    --bindir="/usr/bin" && \
    # PATH="/usr/bin:$PATH" make && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install

# Download and decompress Nginx
RUN mkdir -p /tmp/build/nginx && \
    cd /tmp/build/nginx && \
    wget -O ${NGINX_VERSION}.tar.gz https://nginx.org/download/${NGINX_VERSION}.tar.gz && \
    tar -zxf ${NGINX_VERSION}.tar.gz

# Download and decompress RTMP module
RUN mkdir -p /tmp/build/nginx-rtmp-module && \
    cd /tmp/build/nginx-rtmp-module && \
    wget -O nginx-rtmp-module-${NGINX_RTMP_MODULE_VERSION}.tar.gz https://github.com/arut/nginx-rtmp-module/archive/v${NGINX_RTMP_MODULE_VERSION}.tar.gz && \
    tar -zxf nginx-rtmp-module-${NGINX_RTMP_MODULE_VERSION}.tar.gz && \
    cd nginx-rtmp-module-${NGINX_RTMP_MODULE_VERSION}

# Build and install Nginx
# The default puts everything under /usr/local/nginx, so it's needed to change
# it explicitly. Not just for order but to have it in the PATH
RUN cd /tmp/build/nginx/${NGINX_VERSION} && \
    ./configure \
    --sbin-path=/usr/local/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --pid-path=/var/run/nginx/nginx.pid \
    --lock-path=/var/lock/nginx/nginx.lock \
    --http-log-path=/var/log/nginx/access.log \
    --http-client-body-temp-path=/tmp/nginx-client-body \
    --with-http_ssl_module \
    --with-http_auth_request_module \
    --with-threads \
    --with-ipv6 \
    --add-module=/tmp/build/nginx-rtmp-module/nginx-rtmp-module-${NGINX_RTMP_MODULE_VERSION} --with-debug && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install && \
    mkdir /var/lock/nginx && \
    rm -rf /tmp/build

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt

# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log
