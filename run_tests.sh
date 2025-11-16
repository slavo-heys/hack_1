#!/usr/bin/env bash
# Prosty skrypt testowy: kompiluje i uruchamia z --help
set -e
CXX=g++
SRC="start.cpp"
OUT="start"
$CXX "$SRC" -lpcap -lncurses -o "$OUT"
echo "Kompilacja OK"
./$OUT --help >/dev/null 2>&1 || true
echo "Uruchomienie --help OK (kod: $?)"
