// C corpus for ci/accuracy.py: a spread of function shapes that compilers
// lay out and unwind differently (recursion, struct returns, varargs, VLAs,
// jump tables, cold paths, setjmp/longjmp, indirect calls, qsort callbacks).
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct point {
    double x, y;
};

static jmp_buf recovery;

__attribute__((noinline)) static int square(int x) { return x * x; }

__attribute__((noinline)) static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

__attribute__((noinline)) static struct point midpoint(struct point a, struct point b) {
    struct point m = {(a.x + b.x) / 2, (a.y + b.y) / 2};
    return m;
}

__attribute__((noinline)) static int sum_ints(int count, ...) {
    va_list ap;
    int total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += va_arg(ap, int);
    va_end(ap);
    return total;
}

static int compare_ints(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

__attribute__((noinline)) static size_t vla_checksum(size_t n) {
    unsigned char buf[n];
    for (size_t i = 0; i < n; i++)
        buf[i] = (unsigned char)(i * 31);
    size_t sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += buf[i];
    return sum;
}

__attribute__((noinline)) static const char *classify(int c) {
    switch (c) {
    case 0: return "zero";
    case 1: return "one";
    case 2: return "two";
    case 3: return "three";
    case 4: return "four";
    case 5: return "five";
    case 6: return "six";
    case 7: return "seven";
    default: return "many";
    }
}

__attribute__((noinline, cold)) static void fatal(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    longjmp(recovery, 1);
}

__attribute__((noinline)) static int checked_div(int a, int b) {
    if (__builtin_expect(b == 0, 0))
        fatal("division by zero");
    return a / b;
}

typedef int (*binop)(int, int);
static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static binop ops[] = {add, sub, mul};

int exported_api(int op, int a, int b) { return ops[op % 3](a, b); }

int main(int argc, char **argv) {
    int values[] = {5, 3, 9, 1, argc};
    qsort(values, 5, sizeof values[0], compare_ints);
    struct point m = midpoint((struct point){0, 0}, (struct point){argc, 4});
    printf("%d %ld %.1f %d %zu %s\n", square(argc + 2), fib(15), m.x, sum_ints(3, 1, 2, argc),
           vla_checksum(64 + (size_t)argc), classify(argc));
    if (setjmp(recovery) == 0)
        printf("%d\n", checked_div(10, argc - 1));
    printf("%d\n", exported_api(argc, 6, 7));
    char *copy = strdup(argv[0]);
    printf("%zu\n", strlen(copy));
    free(copy);
    return values[0];
}
