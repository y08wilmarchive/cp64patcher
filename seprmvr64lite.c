#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "patchfinder64.c"

#define GET_OFFSET(klen, x) (x - (uintptr_t) kbuf) // Thanks to @Ralph0045 for this 

addr_t xref_stuff;
void *str_stuff;
addr_t beg_func;

bool dev_kernel = false;
int version;
void* xnu;

int findandpatch(void* kbuf, size_t klen, void* string) {
    //printf("klen: %zu\nkbuf: %p\ncurrent str: %s\nsearch term: %s\n", klen, kbuf, (char *)string, (char *)searchstr);
    str_stuff = memmem(kbuf, klen, string, strlen(string) - 1);
    if (!str_stuff) {
        printf("[-] Failed to find %s string\n", string);
        return -1;
    }
    
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf,0,xref_stuff);

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched %s\n", string);
    return 0;
}

int get_funny_patches(void *kbuf, size_t klen) {
    void* strings[] = {
        "\"Content Protection: uninitialized cnode %p\"",
        "cp_vnode_setclass"
    };
    for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
        if(findandpatch(kbuf, klen, strings[i]) != 0) {
            printf("[-] Failed to patch %s\n", strings[i]);
        }
    }
	return 0;
}

int main(int argc, char* argv[]) {
   if(argc < 3) {
   	    printf("seprmvr64 by mineek\n");
        printf("Usage: %s kcache.raw kcache.pwn\n", argv[0]);
        return 0;
    }

    printf("%s: Starting...\n", __FUNCTION__);

    char *in = argv[1];
	char *out = argv[2];

	void* kbuf;
    size_t klen;

    FILE* fp = fopen(in, "rb");
    if (!fp) {
        printf("[-] Failed to open kernel\n");
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    klen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kbuf = (void*)malloc(klen);
    if(!kbuf) {
        printf("[-] Out of memory\n");
        fclose(fp);
        exit(1);
    }
    fread(kbuf, 1, klen, fp);
    fclose(fp);

    get_funny_patches(kbuf, klen);

    printf("[*] Writing out patched file to %s\n", out);
    fp = fopen(out, "wb+");
        fwrite(kbuf, 1, klen, fp);
        fflush(fp);
    fclose(fp);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    free(kbuf);
    exit(0);
}
