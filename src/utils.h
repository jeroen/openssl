#define stop(...) Rf_errorcall(R_NilValue, __VA_ARGS__)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
void bail(int out);
void raise_error();
int my_nist2nid(const char *name);
