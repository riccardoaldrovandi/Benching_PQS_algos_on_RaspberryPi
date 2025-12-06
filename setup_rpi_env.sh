#!/usr/bin/env bash
set -euo pipefail

### CONFIGURATION ###
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PAPI_DIR="$HOME/papi"
LIBOQS_DIR="$HOME/liboqs"

# Optional: pin specific commits / tags
PAPI_CHECKOUT=""
LIBOQS_CHECKOUT=""

### UTIL FUNCTIONS ###

log() {
    echo -e "\033[1;32m[INFO]\033[0m $*"
}

warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

err() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
}

ensure_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Command '$1' not found. Install it or add it to PATH."
        exit 1
    fi
}

ensure_pkg() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        log "Package already installed: $pkg"
    else
        log "Installing package: $pkg"
        sudo apt-get install -y "$pkg"
    fi
}

detect_arch() {
    local arch
    if command -v dpkg >/dev/null 2>&1; then
        arch="$(dpkg --print-architecture)"
    else
        arch="$(uname -m)"
    fi
    echo "$arch"
}

### 1. Base packages ###

install_base_packages() {
    log "Installing base build packages via apt..."
    sudo apt-get update
    ensure_pkg build-essential
    ensure_pkg cmake
    ensure_pkg git
    ensure_pkg pkg-config
    ensure_pkg libssl-dev
    ensure_pkg autoconf
    ensure_pkg automake
    ensure_pkg libtool
}

### 2. PAPI from GitHub ###

install_papi() {
    log "Setting up PAPI from GitHub (icl-utk-edu/papi)..."

    if [[ -d "$PAPI_DIR" ]]; then
        log "PAPI directory already exists: $PAPI_DIR, fetching updates."
        cd "$PAPI_DIR"
        git fetch --all --prune
    else
        git clone https://github.com/icl-utk-edu/papi.git "$PAPI_DIR"
        cd "$PAPI_DIR"
    fi

    if [[ -n "$PAPI_CHECKOUT" ]]; then
        log "Checking out PAPI at $PAPI_CHECKOUT"
        git checkout "$PAPI_CHECKOUT"
    fi

    cd "$PAPI_DIR/src"
    log "Configuring PAPI with prefix=/usr/local..."
    ./configure --prefix=/usr/local

    log "Building PAPI..."
    make -j"$(nproc)"

    log "Installing PAPI into /usr/local (sudo)..."
    sudo make install

    if [[ -f /usr/local/include/papi.h ]]; then
        log "PAPI installed: /usr/local/include/papi.h found."
    else
        warn "papi.h not found in /usr/local/include – check installation if linking fails later."
    fi
}

### 3. liboqs with all algorithms enabled ###

install_liboqs() {
    log "Setting up liboqs (Open Quantum Safe)..."

    if [[ -d "$LIBOQS_DIR" ]]; then
        log "liboqs directory already exists: $LIBOQS_DIR, fetching updates."
        cd "$LIBOQS_DIR"
        git fetch --all --prune
    else
        git clone https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_DIR"
        cd "$LIBOQS_DIR"
    fi

    if [[ -n "$LIBOQS_CHECKOUT" ]]; then
        log "Checking out liboqs at $LIBOQS_CHECKOUT"
        git checkout "$LIBOQS_CHECKOUT"
    fi

    mkdir -p build
    cd build

    log "Configuring liboqs with OpenSSL, all KEM+SIG enabled, install prefix=/usr/local..."
    cmake \
        -DOQS_USE_OPENSSL=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD=OFF \
        -DOQS_ENABLE_KEM=ON \
        -DOQS_ENABLE_SIG=ON \
        ..

    log "Building liboqs..."
    make -j"$(nproc)"

    log "Installing liboqs into /usr/local (sudo)..."
    sudo make install

    log "Updating library cache with ldconfig..."
    if command -v ldconfig >/dev/null 2>&1; then
        sudo ldconfig
    fi

    if [[ -f /usr/local/lib/liboqs.so ]] || [[ -f /usr/local/lib/liboqs.a ]]; then
        log "liboqs present in /usr/local/lib"
    else
        warn "liboqs not found in /usr/local/lib – check installation if linker errors appear."
    fi
}

### 4. Patch Makefile (paths, flags) ###

patch_makefile() {
    local makefile="$REPO_ROOT/Makefile"
    if [[ ! -f "$makefile" ]]; then
        warn "Makefile not found in $REPO_ROOT, skipping Makefile patch."
        return
    fi

    log "Patching Makefile: $makefile"

    # Remove hardcoded /home/ricca/liboqs/build/lib
    if grep -q "/home/ricca/liboqs/build/lib" "$makefile"; then
        log "Removing hardcoded /home/ricca/liboqs/build/lib from LDFLAGS..."
        sed -i 's|-L/home/ricca/liboqs/build/lib ||g' "$makefile"
    fi

    # Ensure -L/usr/local/lib is in LDFLAGS
    if ! grep -q "LDFLAGS = .* -L/usr/local/lib" "$makefile"; then
        log "Adding -L/usr/local/lib to LDFLAGS..."
        sed -i 's/^LDFLAGS = /LDFLAGS = -L\/usr\/local\/lib /' "$makefile" || true
    fi

    # Ensure -I/usr/local/include is in CFLAGS
    if ! grep -q "CFLAGS = .* -I/usr/local/include" "$makefile"; then
        log "Adding -I/usr/local/include to CFLAGS..."
        sed -i 's/^CFLAGS = /CFLAGS = -I\/usr\/local\/include /' "$makefile" || true
    fi
}

### 5. Normalize opt32/opt64 according to architecture ###

patch_opt_dirs() {
    local arch
    arch="$(detect_arch)"
    log "Detected architecture: $arch"

    # Define "64-bit" and "32-bit" buckets
    case "$arch" in
        arm64|aarch64|amd64|x86_64)
            log "64-bit OS detected – enforcing /opt64/ everywhere (replacing /opt32/ -> /opt64/)..."

            find "$REPO_ROOT" \
                -path "$REPO_ROOT/.git" -prune -o \
                -type f \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) -print0 \
                | xargs -0 sed -i 's/\/opt32\//\/opt64\//g'

            log "All /opt32/ paths switched to /opt64/."
            ;;
        armhf|arm|armv7l|armv6l|i386)
            log "32-bit OS detected – enforcing /opt32/ everywhere (replacing /opt64/ -> /opt32/)..."

            find "$REPO_ROOT" \
                -path "$REPO_ROOT/.git" -prune -o \
                -type f \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) -print0 \
                | xargs -0 sed -i 's/\/opt64\//\/opt32\//g'

            log "All /opt64/ paths switched to /opt32/."
            ;;
        *)
            warn "Unknown architecture '$arch' – leaving opt32/opt64 paths untouched."
            ;;
    esac
}

### 6. Quick link test for liboqs + PAPI ###

test_compile_small() {
    log "Quick test: compile and link a small program against liboqs + PAPI..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    cat > "$tmpdir/test_libs.c" << 'EOF'
#include <stdio.h>
#include <oqs/oqs.h>
#include <papi.h>
int main(void) {
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    int ret = PAPI_library_init(PAPI_VER_CURRENT);
    if (ret != PAPI_VER_CURRENT) {
        fprintf(stderr, "PAPI init failed: %d\n", ret);
        return 1;
    }
    printf("PAPI init OK\n");
    return 0;
}
EOF

    (
        cd "$tmpdir"
        if gcc test_libs.c -o test_libs -I/usr/local/include -L/usr/local/lib -loqs -lpapi -lcrypto -lm; then
            log "test_libs compiled successfully, running..."
            ./test_libs || warn "Running test_libs failed – check output above."
        else
            warn "Compiling test_libs failed – check include paths and lib installation."
        fi
    )

    rm -rf "$tmpdir"
}

### MAIN ###

main() {
    ensure_cmd gcc
    ensure_cmd git
    ensure_cmd cmake
    command -v dpkg >/dev/null 2>&1 || warn "dpkg not found, falling back to uname -m for architecture detection."

    install_base_packages
    install_papi
    install_liboqs
    patch_makefile
    patch_opt_dirs
    test_compile_small

    log "Setup completed. You can now build the project with 'make' in:"
    echo "    $REPO_ROOT"
}

main "$@"
