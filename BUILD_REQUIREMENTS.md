# IridiumOS Build Requirements

This document lists all the tools and dependencies required to build IridiumOS.

## Platform Requirements

- **Operating System**: Linux (x86/x86_64)
  - IridiumOS will **NOT** build on Windows
  - Use Linux VM or WSL on Windows
  - macOS is not officially supported

## Core Build Tools

### Essential Tools
- **make** - Build automation tool
- **git** - Version control (for cloning with submodules)
- **gcc** - GNU C Compiler
  - On Debian/Ubuntu x86_64: `gcc-multilib` package required
- **clang** - C language compiler (used by v86 build)

### Node.js Ecosystem
- **node.js** - JavaScript runtime (recent version recommended, tested with Node 22)
- **npm** - Node package manager (comes with Node.js)

### Rust Toolchain
- **rustup** - Rust toolchain installer
- **Rust targets**:
  - `wasm32-unknown-unknown` (for WebAssembly builds)
  - `i686-unknown-linux-gnu` (for 32-bit Linux rootfs builds)
- **Rust channel**: nightly (configured in `rust-toolchain.toml`)

Install Rust targets with:
```bash
rustup target add wasm32-unknown-unknown
rustup target add i686-unknown-linux-gnu
```

### Additional Build Dependencies
- **java** - Java Runtime Environment (version 11+, for closure compiler)
- **wasm-opt** - WebAssembly optimizer
- **jq** - Command-line JSON processor
- **uuid-runtime** - UUID generation utilities (provides `uuidgen` command)
- **inotifytools** - File system event monitoring tools
- **wget** or **curl** - For downloading external assets

### System Libraries
- **glibc** (32-bit) - GNU C Library 32-bit version
  - On Arch Linux: `lib32-glibc`
  - On Debian/Ubuntu: included in `gcc-multilib`

## Optional Dependencies (for Full Builds)

### For Building Linux RootFS
- **docker** - Container platform for building Alpine Linux rootfs
  - User must be in the docker group: `usermod -a -G docker $USER`
- **losetup** - Loop device management (usually part of util-linux)
- **sudo** - Required for mounting loop devices during rootfs build
- **dd** - Disk duplication utility (usually pre-installed)
- **mkfs.ext4** - ext4 filesystem creation tool
- **tar** - Archive utility

## NPM Dependencies

The following are installed automatically via `npm install`:

### Production Dependencies
- @mercuryworkshop/bare-mux
- @titaniumnetwork-dev/ultraviolet
- autoprefixer
- comlink
- fflate
- filer
- fs-readdir-recursive
- idb-keyval
- libcurl.js
- mime
- onchange
- postcss
- postcss-cli
- typescript

### Development Dependencies
- eslint
- eslint-plugin-html
- eslint-plugin-jsdoc
- @typescript-eslint/eslint-plugin
- @typescript-eslint/parser
- @eslint/eslintrc
- @eslint/js
- @types/node
- @types/wicg-file-system-access
- dreamland
- globals
- prettier
- rollup
- workbox-build

## Quick Installation Guide

### Debian/Ubuntu
```bash
sudo apt update
sudo apt install -y \
  build-essential \
  gcc-multilib \
  clang \
  default-jre \
  git \
  wget \
  curl \
  uuid-runtime \
  inotifytools \
  jq \
  docker.io

# Install Node.js (via NodeSource for latest version)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup target add wasm32-unknown-unknown i686-unknown-linux-gnu

# Install wasm-opt (via Binaryen)
sudo apt install -y binaryen

# Add user to docker group (logout/login required after this)
sudo usermod -a -G docker $USER
```

### Arch Linux
```bash
sudo pacman -S \
  base-devel \
  clang \
  jdk-openjdk \
  git \
  wget \
  curl \
  util-linux \
  inotifytools \
  jq \
  docker \
  binaryen \
  lib32-glibc

# Install Node.js
sudo pacman -S nodejs npm

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup target add wasm32-unknown-unknown i686-unknown-linux-gnu

# Add user to docker group
sudo usermod -a -G docker $USER
```

### Fedora/RHEL
```bash
sudo dnf install -y \
  @development-tools \
  gcc-multilib \
  clang \
  java-11-openjdk \
  git \
  wget \
  curl \
  util-linux \
  inotify-tools \
  jq \
  docker \
  binaryen \
  glibc-devel.i686

# Install Node.js
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo dnf install -y nodejs

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup target add wasm32-unknown-unknown i686-unknown-linux-gnu

# Add user to docker group
sudo usermod -a -G docker $USER
```

## Building IridiumOS

After installing all dependencies:

```bash
# Clone repository with submodules
git clone --recursive https://github.com/FixCraft-Inc/IridiumOS.git
cd IridiumOS

# Build (standard build without rootfs)
make all

# Build with Alpine Linux rootfs (requires Docker)
make full

# Run development server
make server
# Access at http://localhost:8000
```

## GitHub Codespaces Quick Setup

For GitHub Codespaces, a simplified setup script is provided:

```bash
source codespace-basic-setup.sh
```

This script automatically installs minimal dependencies and builds the project.

## Verification

To verify your installation, check the following commands are available:

```bash
# Check versions
node --version
npm --version
rustc --version
cargo --version
java -version
make --version
gcc --version
clang --version
jq --version
uuidgen --version
wasm-opt --version

# Check Rust targets
rustup target list --installed | grep -E "wasm32-unknown-unknown|i686-unknown-linux-gnu"

# Check Docker (if building rootfs)
docker --version
docker run hello-world
```

## Troubleshooting

### Common Issues

1. **`uuidgen: command not found`**
   - Install `uuid-runtime` package

2. **`jq: command not found`**
   - Install `jq` package

3. **32-bit library errors on 64-bit system**
   - Install `gcc-multilib` (Debian/Ubuntu) or `lib32-glibc` (Arch)

4. **Rust target not found**
   - Run: `rustup target add wasm32-unknown-unknown i686-unknown-linux-gnu`

5. **Docker permission denied**
   - Add user to docker group: `sudo usermod -a -G docker $USER`
   - Logout and login again for changes to take effect

6. **wasm-opt not found**
   - Install `binaryen` package

## Minimum System Requirements

- **CPU**: x86_64 processor (x86 for native builds)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Disk Space**: ~5GB for full build with dependencies
- **Network**: Required for initial dependency download

## Build Time Estimates

- **Standard build** (`make all`): 5-15 minutes (depending on system specs)
- **Full build with rootfs** (`make full`): 20-40 minutes
- **Subsequent builds**: 1-5 minutes (incremental compilation)
