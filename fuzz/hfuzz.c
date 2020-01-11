#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"

#include "fuzz/hfuzz.h"


#ifdef HFUZZ_FORKSERVER

extern void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);

static void fork_server(void) {
  size_t len;
  const uint8_t *buf = 0;

  while (2) {
    HonggfuzzFetchData(&buf, &len);

    if (lseek(1021, 0, SEEK_SET) == -1) {
      perror("lseek(1021, 0, SEEK_SET");
      exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
      fputs("fork error\n", stderr);
      exit(1);
    }

    // Child
    if (!pid) {
      return;
    }

    // Parent
    int status;
    if (waitpid(pid, &status, 0) <= 0) {
      fputs("waitpid error\n", stderr);
      exit(1);
    }
  }
}
#endif // HFUZZ_FORKSERVER

extern void hfuzzInstrumentInit(void);

abi_ulong hfuzz_qemu_persist_start = 0;
abi_ulong hfuzz_qemu_persist_end = 0;

void hfuzz_qemu_setup(void) {
  char *env_var = NULL;
  rcu_disable_atfork();
  hfuzzInstrumentInit();

  if (getenv("HFUZZ_INST_LIBS")) {
    hfuzz_qemu_start_code = 0;
    hfuzz_qemu_end_code   = (abi_ulong)-1;
  }
  env_var = getenv("HFUZZ_PERSIST_START");
  if (env_var) {
    hfuzz_qemu_persist_start = strtol(env_var, NULL, 0);
  }
  env_var = getenv("HFUZZ_PERSIST_END");
  if (env_var) {
      hfuzz_qemu_persist_end = strtol(env_var, NULL, 0);
  }

#ifdef HFUZZ_FORKSERVER
  fork_server();
#endif // HFUZZ_FORKSERVER
}

extern void hfuzz_trace_cmp4(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);
extern void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);

void HELPER(hfuzz_qemu_trace_cmp_i64)(
        uint64_t cur_loc, uint64_t arg1, uint64_t arg2
    ) {
  hfuzz_trace_cmp8(cur_loc, arg1, arg2);
}

void HELPER(hfuzz_qemu_trace_cmp_i32)(
        uint32_t cur_loc, uint32_t arg1, uint32_t arg2
    ) {
  hfuzz_trace_cmp4(cur_loc, arg1, arg2);
}
