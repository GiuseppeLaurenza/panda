#ifndef __LIBFIOBJ_H__
#define __LIBFIOBJ_H__
struct LibFICbEntry {
    string libname;
    string fnname;
    bool isenter;
    uint32_t numargs;
    libfi_cb_t callback;
    uint32_t entry_size;
};
#endif