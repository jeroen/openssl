#define stop(...) Rf_errorcall(R_NilValue, __VA_ARGS__)
void bail(int out);
void raise_error();
int my_nist2nid(const char *name);
int password_cb(char *buf, int max_size, int rwflag, void *ctx);
