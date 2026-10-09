// C++ corpus for ci/accuracy.py: exceptions, cleanups during unwinding,
// virtual dispatch, templates and standard containers, so that many FDEs
// carry an LSDA.
#include <cstdio>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct Shape {
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char *name() const = 0;
};

struct Circle : Shape {
    explicit Circle(double r) : r(r) {}
    double area() const override { return 3.14159 * r * r; }
    const char *name() const override { return "circle"; }
    double r;
};

struct Rect : Shape {
    Rect(double w, double h) : w(w), h(h) {}
    double area() const override { return w * h; }
    const char *name() const override { return "rect"; }
    double w, h;
};

// The destructor runs while an exception propagates: a cleanup landing pad.
class Tracer {
  public:
    explicit Tracer(const char *what) : what_(what) { std::printf("enter %s\n", what_); }
    ~Tracer() { std::printf("leave %s\n", what_); }

  private:
    const char *what_;
};

template <typename T>
__attribute__((noinline)) T clamp_sum(const std::vector<T> &values, T limit) {
    T total{};
    for (const T &v : values) {
        total += v;
        if (total > limit)
            throw std::out_of_range("limit exceeded");
    }
    return total;
}

__attribute__((noinline)) static double total_area(const std::vector<std::unique_ptr<Shape>> &shapes) {
    Tracer trace("total_area");
    double sum = 0;
    for (const auto &s : shapes)
        sum += s->area();
    return sum;
}

__attribute__((noinline)) static int parse_or_default(const std::string &text, int fallback) {
    try {
        return std::stoi(text);
    } catch (const std::invalid_argument &) {
        return fallback;
    }
}

int main(int argc, char **argv) {
    std::vector<std::unique_ptr<Shape>> shapes;
    shapes.push_back(std::make_unique<Circle>(argc));
    shapes.push_back(std::make_unique<Rect>(2, argc + 1));
    std::map<std::string, int> counts;
    for (const auto &s : shapes)
        counts[s->name()]++;
    std::printf("%.2f %zu\n", total_area(shapes), counts.size());
    std::printf("%d\n", parse_or_default(argc > 1 ? argv[1] : "x", 7));
    try {
        std::printf("%d\n", clamp_sum<int>({1, 2, 3, argc}, 4));
    } catch (const std::exception &e) {
        std::printf("caught: %s\n", e.what());
    }
    std::printf("%.1f\n", clamp_sum<double>({0.5, 1.5}, 10.0));
    return 0;
}
