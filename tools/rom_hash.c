/* Print the hash that librecomp compares a ROM against.
 *
 * port/src/main.cpp needs this value for its GameEntry, and getting it wrong
 * means the ROM is silently rejected and the game never starts. Rather than
 * trust a hand-copied constant, compute it the same way librecomp does --
 * see `check_hash` in librecomp/src/recomp.cpp:
 *
 *     uint64_t calculated_hash = XXH3_64bits(rom_data.data(), rom_data.size());
 *
 * Build (xxHash is a submodule of N64ModernRuntime):
 *
 *   gcc -O2 -I build/n64modernruntime/thirdparty/xxHash \
 *       -o /tmp/rom_hash tools/rom_hash.c \
 *       build/n64modernruntime/thirdparty/xxHash/xxhash.c
 *   /tmp/rom_hash baserom.z64
 */

#include <stdio.h>
#include <stdlib.h>

#include "xxhash.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <rom>\n", argv[0]);
        return 2;
    }

    FILE* file = fopen(argv[1], "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "cannot seek %s\n", argv[1]);
        return 1;
    }
    long size = ftell(file);
    rewind(file);
    if (size <= 0) {
        fprintf(stderr, "%s is empty\n", argv[1]);
        return 1;
    }

    unsigned char* data = malloc((size_t)size);
    if (data == NULL || fread(data, 1, (size_t)size, file) != (size_t)size) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    fclose(file);

    XXH64_hash_t hash = XXH3_64bits(data, (size_t)size);
    printf("0x%016llX  (%llu bytes)\n", (unsigned long long)hash, (unsigned long long)size);
    free(data);
    return 0;
}
