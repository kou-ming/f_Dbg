#include <iostream>
void d() {
    int foo = 4;
}

void e() {
    int foo = 5;
    d();
}

void f() {
    int foo = 6;
    e();
}

int main() {
    f();
	int foo = 7;
	return 0;
}
