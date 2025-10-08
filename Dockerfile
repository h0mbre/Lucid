# Base image
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /lucid

# ------------------------------------------------------------
# 1. Install minimal dependencies for building Musl
# ------------------------------------------------------------
RUN apt update && apt install -y \
    build-essential git autoconf automake libtool pkg-config \
    gawk xz-utils wget \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# 2. Clone musl-cross-make and build toolchain
# ------------------------------------------------------------
RUN git clone https://github.com/richfelker/musl-cross-make.git && \
    cd musl-cross-make && \
    git checkout 26bb55104559325b5e840911742220268f556d7a && \
    make TARGET=x86_64-linux-musl install -j$(nproc)

# ------------------------------------------------------------
# 3. Apply Lucid patches to musl-1.2.4
# ------------------------------------------------------------
COPY patches/musl.patch patches/musl.patch
RUN cd musl-cross-make && \
    patch -p0 < /lucid/patches/musl.patch

# ------------------------------------------------------------
# 4. Reconfigure and reinstall patched Musl
# ------------------------------------------------------------
RUN cd musl-cross-make/musl-1.2.4 && \
    ./configure --prefix=/lucid/musl-cross-make/output/x86_64-linux-musl && \
    make -j$(nproc) && \
    make install

# ------------------------------------------------------------
# 5. Add toolchain to PATH
# ------------------------------------------------------------
ENV PATH="/lucid/musl-cross-make/output/bin:${PATH}"

# ------------------------------------------------------------
# 6. Clone Bochs and checkout pinned commit
# ------------------------------------------------------------
RUN git clone https://github.com/bochs-emu/Bochs.git && \
    cd Bochs && \
    git checkout a9d2e8f41990c05db4a1a2f52383fc7ae51d819b

# ------------------------------------------------------------
# 7. Apply Lucid patches to Bochs
# ------------------------------------------------------------
COPY patches/bochs.patch patches/bochs.patch
RUN cd Bochs && patch -p0 < /lucid/patches/bochs.patch

# ------------------------------------------------------------
# 8. Build lucid_bochs --static-pie against patched Musl
# ------------------------------------------------------------
RUN cd Bochs/bochs && \
    CC="/lucid/musl-cross-make/output/bin/x86_64-linux-musl-gcc" \
    CXX="/lucid/musl-cross-make/output/bin/x86_64-linux-musl-g++" \
    CFLAGS="-Wall -O3 -fomit-frame-pointer --static-pie -fPIE -DBX_LUCID" \
    CXXFLAGS="-Wall -O3 -fomit-frame-pointer --static-pie -fPIE -DBX_LUCID" \
    ./configure \
        --enable-fpu \
        --enable-all-optimizations \
        --enable-long-phy-address \
        --enable-a20-pin \
        --enable-cpu-level=6 \
        --enable-x86-64 \
        --enable-pci \
        --enable-e1000 \
        --enable-avx \
        --enable-instrumentation="instrument/stubs" \
        --disable-large-ramfile \
        --with-nogui && \
    make -j$(nproc) && \
    mkdir -p /lucid/build && \
    cp bochs /lucid/build/lucid-bochs

# ------------------------------------------------------------
# 9. Install GUI dependencies for snapshot Bochs build
# ------------------------------------------------------------
RUN apt update && apt install -y \
    libsdl2-dev libsdl2-image-dev libx11-dev libxext-dev libxrandr-dev \
    libxcursor-dev libxinerama-dev libxss-dev libgl1-mesa-dev libglu1-mesa-dev \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# 10. Build GUI Bochs for snapshotting
# ------------------------------------------------------------
RUN cd Bochs/bochs && \
    make distclean || true && \
    CC="gcc" \
    CXX="g++" \
    CFLAGS="-Wall -O3 -fomit-frame-pointer -pipe -DBX_SNAPSHOT" \
    CXXFLAGS="-Wall -O3 -fomit-frame-pointer -pipe -DBX_SNAPSHOT" \
    ./configure \
        --enable-fpu \
        --enable-all-optimizations \
        --enable-long-phy-address \
        --enable-a20-pin \
        --enable-cpu-level=6 \
        --enable-x86-64 \
        --enable-pci \
        --enable-e1000 \
        --enable-show-ips \
        --enable-avx \
        --disable-large-ramfile \
        --with-sdl2 && \
    make -j$(nproc) && \
    cp bochs /lucid/build/gui-bochs

# ------------------------------------------------------------
# 11. Install latest stable Rust toolchain
# ------------------------------------------------------------
RUN apt update && apt install -y curl && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable && \
    . "$HOME/.cargo/env" && \
    echo 'source $HOME/.cargo/env' >> /root/.bashrc

ENV PATH="/root/.cargo/bin:${PATH}"

# ------------------------------------------------------------
# 12. Copy Lucid source and build it
# ------------------------------------------------------------
COPY . /lucid

RUN cd /lucid && \
    cargo build --release && \
    mkdir -p /lucid/build && \
    cp target/release/lucid-fuzz /lucid/build/lucid-fuzz

# ------------------------------------------------------------
# 13. Copy Bochs BIOS files into build directory for ease-of-use
# ------------------------------------------------------------
RUN cp /lucid/Bochs/bochs/bios/BIOS-bochs-latest /lucid/build/ && \
    cp /lucid/Bochs/bochs/bios/VGABIOS-lgpl-latest /lucid/build/

CMD ["/bin/bash"]
