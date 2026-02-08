#!/bin/bash
# QRTB Native Build & Run Script
MINGW="/c/Users/andre/AppData/Local/Microsoft/WinGet/Packages/BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe/mingw64/bin"
export CC="$MINGW/gcc.exe"
export AR="$MINGW/ar.exe"
export PATH="/usr/bin:/bin:$MINGW:$HOME/.cargo/bin"

case "${1:-run}" in
    build)  cargo +stable-x86_64-pc-windows-gnu build --release ;;
    test)   cargo +stable-x86_64-pc-windows-gnu test --release ;;
    run)    cargo +stable-x86_64-pc-windows-gnu run --release ;;
    bench)  cargo +stable-x86_64-pc-windows-gnu bench ;;
    clean)  cargo clean ;;
    *)      echo "Usage: ./run.sh [build|test|run|bench|clean]" ;;
esac
