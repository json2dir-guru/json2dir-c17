/* json2dir in C17: read a JSON document on stdin, create the tree it
 * describes in the current directory.
 *
 *   gcc -std=c17 -pedantic-errors -Wall -Wextra -O2 -o json2dir json2dir.c
 *   ./json2dir < document.json
 *
 * ISO C17 plus POSIX.1-2008. Hand-written UTF-8 check and JSON parser.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uchar.h>
#include <unistd.h>

enum { MAX_DEPTH = 1000 };

_Static_assert(sizeof(char32_t) >= 4, "char32_t must hold any code point");
_Static_assert((S_IXUSR | S_IXGRP | S_IXOTH) == 0111, "POSIX execute bits");
_Static_assert((0666 & 0111) == 0, "plain files never get execute bits");
_Static_assert(MAX_DEPTH >= 64, "the spec requires at least 64 levels");

/* ---------- diagnostics ------------------------------------------------ */

static noreturn void die_msg(const char *ctx, const char *msg)
{
    fprintf(stderr, "json2dir: %s: %s\n", ctx, msg);
    exit(1);
}

static noreturn void die_errno(const char *ctx, int err)
{
    die_msg(ctx, strerror(err));
}

/* die(ctx, "message") or die(ctx, errno) */
#define die(ctx, what) _Generic((what),        \
        char *: die_msg,                       \
        const char *: die_msg,                 \
        int: die_errno)((ctx), (what))

static void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p)
        die("memory", ENOMEM);
    return p;
}

/* ---------- tree ------------------------------------------------------- */

typedef enum { N_OBJECT, N_FILE, N_SCRIPT, N_LINK } kind_t;

typedef struct { char *data; size_t len; } bytes_t;

typedef struct node node_t;
typedef struct member member_t;

struct node {
    kind_t kind;
    union {
        struct { member_t *members; size_t count; }; /* N_OBJECT */
        bytes_t text;                 /* N_FILE, N_SCRIPT: content; N_LINK: target */
    };
};

struct member {
    bytes_t name;
    node_t value;
};

/* ---------- UTF-8 ------------------------------------------------------ */

static bool utf8_valid(const unsigned char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        size_t len;
        char32_t cp, min;
        if (c < 0x80) { i++; continue; }
        else if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        else return false;
        if (n - i < len)
            return false;
        for (size_t k = 1; k < len; k++) {
            if ((s[i + k] & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        i += len;
    }
    return true;
}

/* ---------- JSON parser ------------------------------------------------ */

typedef struct {
    const char *s;
    size_t pos, len;
} parser_t;

static noreturn void bad(const parser_t *p, const char *msg)
{
    char ctx[64];
    snprintf(ctx, sizeof ctx, "invalid document at byte %zu", p->pos);
    die(ctx, msg);
}

static void skip_ws(parser_t *p)
{
    while (p->pos < p->len && strchr(" \t\r\n", p->s[p->pos]) && p->s[p->pos])
        p->pos++;
}

static int peek(const parser_t *p)
{
    return p->pos < p->len ? (unsigned char)p->s[p->pos] : -1;
}

static void put_byte(bytes_t *b, size_t *cap, char c)
{
    if (b->len + 1 >= *cap) {
        *cap = *cap ? *cap * 2 : 16;
        b->data = xrealloc(b->data, *cap);
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void put_cp(bytes_t *b, size_t *cap, char32_t cp)
{
    if (cp < 0x80) {
        put_byte(b, cap, (char)cp);
    } else if (cp < 0x800) {
        put_byte(b, cap, (char)(0xC0 | (cp >> 6)));
        put_byte(b, cap, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        put_byte(b, cap, (char)(0xE0 | (cp >> 12)));
        put_byte(b, cap, (char)(0x80 | ((cp >> 6) & 0x3F)));
        put_byte(b, cap, (char)(0x80 | (cp & 0x3F)));
    } else {
        put_byte(b, cap, (char)(0xF0 | (cp >> 18)));
        put_byte(b, cap, (char)(0x80 | ((cp >> 12) & 0x3F)));
        put_byte(b, cap, (char)(0x80 | ((cp >> 6) & 0x3F)));
        put_byte(b, cap, (char)(0x80 | (cp & 0x3F)));
    }
}

static char32_t hex4(parser_t *p)
{
    char32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int c = peek(p);
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else bad(p, "bad \\u escape");
        v = (v << 4) | (char32_t)d;
        p->pos++;
    }
    return v;
}

static bytes_t parse_string(parser_t *p)
{
    bytes_t b = { .data = NULL, .len = 0 };
    size_t cap = 0;
    put_byte(&b, &cap, 'x');            /* make sure data is allocated */
    b.len = 0;
    b.data[0] = '\0';
    p->pos++;                           /* opening quote */
    for (;;) {
        int c = peek(p);
        if (c < 0)
            bad(p, "unterminated string");
        p->pos++;
        if (c == '"')
            return b;
        if (c < 0x20)
            bad(p, "control character in string");
        if (c != '\\') {
            put_byte(&b, &cap, (char)c);
            continue;
        }
        c = peek(p);
        p->pos++;
        switch (c) {
        case '"': put_byte(&b, &cap, '"'); break;
        case '\\': put_byte(&b, &cap, '\\'); break;
        case '/': put_byte(&b, &cap, '/'); break;
        case 'b': put_byte(&b, &cap, '\b'); break;
        case 'f': put_byte(&b, &cap, '\f'); break;
        case 'n': put_byte(&b, &cap, '\n'); break;
        case 'r': put_byte(&b, &cap, '\r'); break;
        case 't': put_byte(&b, &cap, '\t'); break;
        case 'u': {
            char32_t cp = hex4(p);
            if (cp >= 0xDC00 && cp <= 0xDFFF)
                bad(p, "unpaired surrogate");
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (peek(p) != '\\' || p->pos + 1 >= p->len || p->s[p->pos + 1] != 'u')
                    bad(p, "unpaired surrogate");
                p->pos += 2;
                char32_t lo = hex4(p);
                if (lo < 0xDC00 || lo > 0xDFFF)
                    bad(p, "unpaired surrogate");
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            }
            put_cp(&b, &cap, cp);
            break;
        }
        default:
            p->pos--;
            bad(p, "bad escape");
        }
    }
}

static void check_name(const parser_t *p, bytes_t name)
{
    if (name.len == 0)
        bad(p, "empty name");
    if (strcmp(name.data, ".") == 0 || strcmp(name.data, "..") == 0)
        bad(p, "name is . or ..");
    if (memchr(name.data, '/', name.len))
        bad(p, "name contains /");
    if (memchr(name.data, '\0', name.len))
        bad(p, "name contains NUL");
}

static void expect(parser_t *p, char c, const char *msg)
{
    skip_ws(p);
    if (peek(p) != (unsigned char)c)
        bad(p, msg);
    p->pos++;
}

static node_t parse_value(parser_t *p, int depth);

static node_t parse_object(parser_t *p, int depth)
{
    if (depth > MAX_DEPTH)
        bad(p, "nesting too deep");
    node_t n = { .kind = N_OBJECT, .members = NULL, .count = 0 };
    size_t cap = 0;
    p->pos++;                           /* { */
    skip_ws(p);
    if (peek(p) == '}') {
        p->pos++;
        return n;
    }
    for (;;) {
        skip_ws(p);
        if (peek(p) != '"')
            bad(p, "expected member name");
        bytes_t name = parse_string(p);
        check_name(p, name);
        expect(p, ':', "expected ':'");
        node_t v = parse_value(p, depth + 1);
        if (n.count == cap) {
            cap = cap ? cap * 2 : 4;
            n.members = xrealloc(n.members, cap * sizeof *n.members);
        }
        n.members[n.count++] = (member_t){ .name = name, .value = v };
        skip_ws(p);
        int c = peek(p);
        p->pos++;
        if (c == '}')
            return n;
        if (c != ',') {
            p->pos--;
            bad(p, "expected ',' or '}'");
        }
    }
}

static node_t parse_array(parser_t *p)
{
    bytes_t items[2];
    size_t count = 0;
    p->pos++;                           /* [ */
    skip_ws(p);
    if (peek(p) != ']') {
        for (;;) {
            skip_ws(p);
            if (peek(p) != '"')
                bad(p, "array elements must be strings");
            bytes_t s = parse_string(p);
            if (count == 2)
                bad(p, "array must have exactly two elements");
            items[count++] = s;
            skip_ws(p);
            int c = peek(p);
            p->pos++;
            if (c == ']')
                break;
            if (c != ',') {
                p->pos--;
                bad(p, "expected ',' or ']'");
            }
        }
    } else {
        p->pos++;
    }
    if (count != 2)
        bad(p, "array must have exactly two elements");
    kind_t kind;
    if (strcmp(items[0].data, "link") == 0 && items[0].len == 4)
        kind = N_LINK;
    else if (strcmp(items[0].data, "script") == 0 && items[0].len == 6)
        kind = N_SCRIPT;
    else
        bad(p, "array kind must be \"link\" or \"script\"");
    free(items[0].data);
    if (kind == N_LINK && (items[1].len == 0 || memchr(items[1].data, '\0', items[1].len)))
        bad(p, "link target must be non-empty and contain no NUL");
    return (node_t){ .kind = kind, .text = items[1] };
}

static node_t parse_value(parser_t *p, int depth)
{
    skip_ws(p);
    switch (peek(p)) {
    case '{': return parse_object(p, depth);
    case '[': return parse_array(p);
    case '"': return (node_t){ .kind = N_FILE, .text = parse_string(p) };
    case -1:  bad(p, "unexpected end of input");
    default:  bad(p, "numbers, true, false and null are not allowed");
    }
}

/* ---------- writing the tree ------------------------------------------ */

static void write_all(int fd, const bytes_t *b, const char *name)
{
    size_t off = 0;
    while (off < b->len) {
        ssize_t w = write(fd, b->data + off, b->len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            die(name, errno);
        }
        off += (size_t)w;
    }
}

static void build(int dfd, const node_t *obj);

static void make_entry(int dfd, const char *name, const node_t *v)
{
    struct stat st;
    bool exists = fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (!exists && errno != ENOENT)
        die(name, errno);

    if (v->kind == N_OBJECT) {
        if (!exists || !S_ISDIR(st.st_mode)) {
            if (exists && unlinkat(dfd, name, 0) != 0)
                die(name, errno);
            if (mkdirat(dfd, name, 0777) != 0)
                die(name, errno);
        }
        int sub = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (sub < 0)
            die(name, errno);
        build(sub, v);
        close(sub);
        return;
    }

    if (exists) {
        if (S_ISDIR(st.st_mode))
            die(name, "a directory is in the way");
        if (unlinkat(dfd, name, 0) != 0)
            die(name, errno);
    }

    if (v->kind == N_LINK) {
        if (symlinkat(v->text.data, dfd, name) != 0)
            die(name, errno);
        return;
    }

    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
    if (fd < 0)
        die(name, errno);
    write_all(fd, &v->text, name);
    if (v->kind == N_SCRIPT) {
        if (fstat(fd, &st) != 0 || fchmod(fd, (st.st_mode & 07777) | 0111) != 0)
            die(name, errno);
    }
    if (close(fd) != 0)
        die(name, errno);
}

static bool same_name(const bytes_t *a, const bytes_t *b)
{
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

static void build(int dfd, const node_t *obj)
{
    for (size_t i = 0; i < obj->count; i++) {
        bool later = false;             /* duplicate names: last one wins */
        for (size_t j = i + 1; j < obj->count && !later; j++)
            later = same_name(&obj->members[i].name, &obj->members[j].name);
        if (!later)
            make_entry(dfd, obj->members[i].name.data, &obj->members[i].value);
    }
}

/* ---------- main ------------------------------------------------------- */

static bytes_t read_stdin(void)
{
    alignas(max_align_t) char buf[65536];
    bytes_t b = { .data = NULL, .len = 0 };
    size_t cap = 0;
    for (;;) {
        ssize_t r = read(STDIN_FILENO, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            die("stdin", errno);
        }
        if (r == 0)
            return b;
        if (b.len + (size_t)r > cap) {
            cap = (b.len + (size_t)r) * 2;
            b.data = xrealloc(b.data, cap);
        }
        memcpy(b.data + b.len, buf, (size_t)r);
        b.len += (size_t)r;
    }
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc > 1) {
        fputs("usage: json2dir < document.json\n", stderr);
        return 2;
    }
    bytes_t in = read_stdin();
    if (!utf8_valid((const unsigned char *)in.data, in.len))
        die("input", "not valid UTF-8");

    parser_t p = { .s = in.data, .pos = 0, .len = in.len };
    if (p.len >= 3 && memcmp(p.s, "\xEF\xBB\xBF", 3) == 0)
        p.pos = 3;                      /* tolerate a byte order mark */
    skip_ws(&p);
    if (peek(&p) != '{')
        bad(&p, peek(&p) < 0 ? "empty document" : "root must be an object");
    node_t root = parse_value(&p, 0);
    skip_ws(&p);
    if (p.pos != p.len)
        bad(&p, "trailing data after document");

    build(AT_FDCWD, &root);
    return 0;
}
