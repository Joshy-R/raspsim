//
// PTLsim: Cycle Accurate x86-64 Simulator
// RASPsim application
//
// Copyright 2020-2020 Alexis Engelke <engelke@in.tum.de>
//

#include <globals.h>
#include <superstl.h>
#include <mm.h>

#include <elf.h>

#include <ptlsim.h>
#include <ptlsim-api.h>
#include <ptlhwdef.h>
#include <config.h>
#include <stats.h>
#include <raspsim-hwsetup.h>

struct PTLsimConfig;
extern PTLsimConfig config;

extern ConfigurationParser<PTLsimConfig> configparser;



extern "C" void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  stringbuf sb;
  sb << "Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ") at ", sim_cycle, " cycles, ", iterations, " iterations, ", total_user_insns_committed, " user commits", endl;

  cerr << sb, flush;

  if (logfile) {
    logfile << sb, flush;
    PTLsimMachine* machine = PTLsimMachine::getcurrent();
    if (machine) machine->dump_state(logfile);
    logfile.close();
  }

  sys_exit(1); // Well, we don't want core dumps.

  // Crash and make a core dump:
  asm("ud2a");
  abort();
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  requested_switch_to_native = 1; // exit
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}


// Saved and restored by asm code:
FXSAVEStruct x87state;
W16 saved_cs;
W16 saved_ss;
W16 saved_ds;
W16 saved_es;
W16 saved_fs;
W16 saved_gs;

void Raspsim::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  Context& ctx{Raspsim::getContext()};

  Waddr rip = ctx.commitarf[REG_selfrip];

  logfile << "Exception ", exception, " (", x86_exception_names[exception], ") code=", errorcode, " addr=", (void*)virtaddr, " @ rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;
  cerr << "Exception ", exception, " (", x86_exception_names[exception], ") code=", errorcode, " addr=", (void*)virtaddr, " @ rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;

  // PF
  if (exception == 14) {
    // PF Flags
    W8 p    = errorcode & 0x00000001;
    W8 wr   = errorcode & 0x00000002;
    W8 us   = errorcode & 0x00000004;
    W8 rsvd = errorcode & 0x00000008;
    W8 id   = errorcode & 0x00000010;
    W8 pk   = errorcode & 0x00000020;

    logfile << "PageFault error code: 0x", hexstring(errorcode, 32), ", Flags: ", (pk ? "PK " : ""), (id ? "I " : "D "), (rsvd ? "RSVD " : ""), (us ? "U " : "S "), (wr ? "W " : "R "), (p ? "P" : ""), endl, flush;
    cerr    << "PageFault error code: 0x", hexstring(errorcode, 32), ", Flags: ", (pk ? "PK " : ""), (id ? "I " : "D "), (rsvd ? "RSVD " : ""), (us ? "U " : "S "), (wr ? "W " : "R "), (p ? "P" : ""), endl, flush;
  }

  cerr << "End state:", endl;
  cerr << ctx, endl;
  exit(1);
}

#ifdef __x86_64__

const char* syscall_names_64bit[] = {
  "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid"};

//
// SYSCALL instruction from x86-64 mode
//
void Raspsim::handle_syscall_64bit() {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle an x86-64 syscall:
  // (This is called from the assist_syscall ucode assist)
  //
  Context& ctx{Raspsim::getContext()};

  size_t syscallid = ctx.commitarf[REG_rax];
  W64 arg1 = ctx.commitarf[REG_rdi];
  W64 arg2 = ctx.commitarf[REG_rsi];
  W64 arg3 = ctx.commitarf[REG_rdx];
  W64 arg4 = ctx.commitarf[REG_r10];
  W64 arg5 = ctx.commitarf[REG_r8];
  W64 arg6 = ctx.commitarf[REG_r9];

  if (DEBUG)
    logfile << "handle_syscall -> (#", syscallid, " ", ((syscallid < (size_t)lengthof(syscall_names_64bit)) ? syscall_names_64bit[syscallid] : "???"),
      ") from ", (void*)ctx.commitarf[REG_rcx], " args ", " (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, ", ",
      (void*)arg5, ", ", (void*)arg6, ") at iteration ", iterations, endl, flush;

  ctx.commitarf[REG_rax] = -ENOSYS;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx];

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)ctx.commitarf[REG_rax], "); returning to ", (void*)ctx.commitarf[REG_rip], endl, flush;
}

#endif // __x86_64__

void Raspsim::handle_syscall_32bit(int semantics) {
  Context& ctx{Raspsim::getContext()};

  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle a 32-bit syscall:
  // (This is called from the assist_syscall ucode assist)
  //
  if (semantics == SYSCALL_SEMANTICS_INT80) {
    // Our exit operation.
    requested_switch_to_native = 1;
  } else {
    // But don't clobber RAX when we want out guest to quit.
    ctx.commitarf[REG_rax] = -ENOSYS;
  }

  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}


bool handle_config_arg(Raspsim& sim, char* line, dynarray<Waddr>* dump_pages) {
  if (*line == '\0') return false;
  dynarray<char*> toks;
  toks.tokenize(line, " ");
  if (toks.empty())
    return false;

  if (toks[0][0] == '#') {
    return false;
  }

  if (toks[0][0] == 'M') { // allocate page M<addr> <prot>
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0' || lowbits(addr, 12)) {
      cerr << "Error: invalid value ", toks[0], " ", endp, endl;
      return true;
    }
    int prot = 0;
    if (!strcmp(toks[1], "ro")) prot = PROT_READ;
    else if (!strcmp(toks[1], "rw")) prot = PROT_READ | PROT_WRITE;
    else if (!strcmp(toks[1], "rx")) prot = PROT_READ | PROT_EXEC;
    else if (!strcmp(toks[1], "rwx")) prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    else {
      cerr << "Error: invalid mem prot ", toks[1], endl;
      return true;
    }
    sim.mmap(addr, 0x1000, prot);
  } else if (toks[0][0] == 'W') { // write to mem W<addr> <hexbytes>, may not cross page boundaries
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[0], endl;
      return true;
    }
    W8* mapped = (W8*)sim.getMappedPage(addr);
    if (!mapped) {
      cerr << "Error: page not mapped ", (void*) addr, endl;
      return true;
    }
    Waddr arglen = strlen(toks[1]);
    if ((arglen & 1) || arglen/2 > 4096-lowbits(addr, 12)) {
      cerr << "Error: arg has odd size or crosses page boundary", (void*) addr, endl;
      return true;
    }
    unsigned n = min((Waddr)(4096 - lowbits(addr, 12)), arglen/2);
    foreach (i, n) {
      char hex_byte[3] = {toks[1][i*2],toks[1][i*2+1], 0};
      mapped[i] = strtoul(hex_byte, NULL, 16);
    }
  } else if (toks[0][0] == 'D') { // dump page D<page>
    if (toks.size() != 1) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[0], endl;
      return true;
    }
    dump_pages->push(floor(addr, PAGE_SIZE));
  } else if (!strcmp(toks[0], "Fnox87")) {
    sim.disableX87();
  } else if (!strcmp(toks[0], "Fnosse")) {
    sim.disableSSE();
  } else if (!strcmp(toks[0], "Fnocache")) {
    sim.enablePerfectCache();
  } else if (!strcmp(toks[0], "Fstbrpred")) {
    sim.enableStaticBranchPrediction();
  } else {
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    int reg = sim.getRegisterIndex(toks[0]);
    if (reg < 0) {
      cerr << "Error: invalid register ", toks[0], endl;
      return true;
    }
    char* endp;
    W64 v = strtoull(toks[1], &endp, 0);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[1], endl;
      return true;
    }
    sim.setRegisterValue(reg, v);
  }

  return false;
}

//
// PTLsim main: called after ptlsim_preinit() brings up boot subsystems
//
 int main(int argc, char** argv) {    
  configparser.setup();
  config.reset();

  int ptlsim_arg_count = 1 + configparser.parse(config, argc-1, argv+1);
  if (ptlsim_arg_count == 0) ptlsim_arg_count = argc;
  handle_config_change(config, ptlsim_arg_count - 1, argv+1);

  Raspsim sim{};
  dynarray<Waddr> dump_pages;
  // TODO(AE): set seccomp filter before parsing arguments
  bool parse_err = false;
  for (unsigned i = ptlsim_arg_count; i < argc; i++) {
    if (argv[i][0] == '@') {
      stringbuf line;
      istream is(argv[i] + 1);
      if (!is) {
        cerr << "Warning: cannot open command list file '", argv[i], "'", endl;
        continue;
      }  
      for (;;) {
        line.reset();
        if (!is) break;
        is >> line;  
        char* p = strchr(line, '#');
        if (p) *p = 0;
        parse_err |= handle_config_arg(sim, line, &dump_pages);
      }
    } else {
      parse_err |= handle_config_arg(sim, argv[i], &dump_pages);
    }
  }  
  if (parse_err) {
    cerr << "Error: could not parse all arguments", endl, flush;
    sys_exit(1);
  }

  logfile << endl,  "=== Switching to simulation mode at rip ", (void*)(Waddr) sim.getRegisterValue(REG_rip), " ===", endl, endl, flush;
  logfile << "Baseline state:", endl;
  logfile << sim.getContext();

  sim.run();

  cerr << "End state:", endl;
  cerr << sim.getContext(), endl;

  foreach (i, dump_pages.length) {
    Waddr addr = dump_pages[i];
    byte* mapped = sim.getMappedPage(addr);
    if (!mapped) {
      cerr << "Error dumping memory: page not mapped ", (void*) addr, endl;
    } else {
      cerr << "Dump of memory at ", (void*) addr, ": ", endl;
      cerr << bytestring(mapped, PAGE_SIZE), endl;
    }
  }
  
  cerr << "Decoder stats:";
  foreach(i, DECODE_TYPE_COUNT) {
    cerr << " ", decode_type_names[i], "=", stats.decoder.x86_decode_type[i];
  }
  cerr << endl;
  cerr << flush;

  cerr << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr) sim.getRegisterValue(REG_rip), " (",
    sim_cycle, " cycles, ", total_user_insns_committed, " user commits, ", iterations, " iterations) ===", endl, endl;

  Raspsim::stutdown();

  sys_exit(0);
}
bool requested_switch_to_native = 0;
