// mayhem shim: the upstream unit tests built by mayhem/build.sh include "proxysql.h" only for the
// standard headers it re-exports; the tokenizer/PROXY-protocol units they test need nothing else.
#ifndef MAYHEM_SHIM_PROXYSQL_H
#define MAYHEM_SHIM_PROXYSQL_H
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#endif
