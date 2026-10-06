# json2dir-c17

json2dir in C17: one file, ISO C17 + POSIX only, hand-written UTF-8 check and JSON parser.

    gcc -std=c17 -pedantic-errors -Wall -Wextra -O2 -o json2dir json2dir.c && ./json2dir < document.json
