//
// PTLsim: Cycle Accurate x86-64 Simulator
// Shared Functions and Structures
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#define CPT_STATS
#include <stats.h>
#undef CPT_STATS

#include <elf.h>

#ifndef CONFIG_ONLY
//
// Global variables
//
PTLsimConfig config;
ConfigurationParser<PTLsimConfig> configparser;
PTLsimStats stats;

ostream logfile;
bool logenable = 0;
W64 sim_cycle = 0;
W64 unhalted_cycle_count = 0;
W64 iterations = 0;
W64 total_uops_executed = 0;
W64 total_uops_committed = 0;
W64 total_user_insns_committed = 0;
W64 total_basic_blocks_committed = 0;
#endif

void PTLsimConfig::reset() {
#ifdef PTLSIM_HYPERVISOR
  domain = (W64)(-1);
  run = 0;
  stop = 0;
  native = 0;
  kill = 0;
  flush_command_queue = 0;
  simswitch = 0;
#endif

  quiet = 0;
  core_name = "ooo";
  log_filename = "ptlsim.log";
  start_log_at_iteration = 0;
  start_log_at_rip = INVALIDRIP;
  log_on_console = 0;
  log_ptlsim_boot = 0;
  log_buffer_size = 524288;
  mm_logfile.reset();
  mm_log_buffer_size = 16384;
  enable_inline_mm_logging = 0;
  enable_mm_validate = 0;

  event_log_enabled = 0;
  event_log_ring_buffer_size = 32768;
  flush_event_log_every_cycle = 0;
  log_backwards_from_trigger_rip = INVALIDRIP;
  dump_state_now = 0;
  abort_at_end = 0;

#ifndef PTLSIM_HYPERVISOR
  // Starting Point
  start_at_rip = INVALIDRIP;
  include_dyn_linker = 1;
  trigger_mode = 0;
  pause_at_startup = 0;
#endif

  stop_at_user_insns = infinity;
  stop_at_iteration = infinity;
  stop_at_rip = INVALIDRIP;

#ifdef PTLSIM_HYPERVISOR
  event_trace_record_filename.reset();
  event_trace_record_stop = 0;
  event_trace_replay_filename.reset();

  core_freq_hz = 0;
  // default timer frequency is 100 hz in time-xen.c:
  timer_interrupt_freq_hz = 100;
  pseudo_real_time_clock = 0;
  realtime = 0;
  mask_interrupts = 0;
  console_mfn = 0;
  pause = 0;
  perfctr_name.reset();
  force_native = 0;
#endif

  perfect_cache = 0;
  static_branchpred = 0;

  bbcache_dump_filename.reset();

#ifndef PTLSIM_HYPERVISOR
  sequential_mode_insns = 0;
  exit_after_fullsim = 0;
#endif
}

template <>
void ConfigurationParser<PTLsimConfig>::setup() {
#ifdef PTLSIM_HYPERVISOR
  // Full system only
  section("PTLmon Control");
  add(domain,                       "domain",               "Domain to access");

  section("Action (specify only one)");
  add(run,                          "run",                  "Run under simulation");
  add(stop,                         "stop",                 "Stop current simulation run and wait for command");
  add(native,                       "native",               "Switch to native mode");
  add(kill,                         "kill",                 "Kill PTLsim inside domain (and ptlmon), then shutdown domain");
  add(flush_command_queue,          "flush",                "Flush all queued commands, stop the current simulation run and wait");
  add(simswitch,                    "switch",               "Switch back to PTLsim while in native mode");
#endif

  section("Simulation Control");

  add(core_name,                    "core",                 "Run using specified core (-core <corename>)");

  section("General Logging Control");
  add(quiet,                        "quiet",                "Do not print PTLsim system information banner");
  add(log_filename,                 "logfile",              "Log filename (use /dev/fd/1 for stdout, /dev/fd/2 for stderr)");
  add(loglevel,                     "loglevel",             "Log level (0 to 99)");
  add(start_log_at_iteration,       "startlog",             "Start logging after iteration <startlog>");
  add(start_log_at_rip,             "startlogrip",          "Start logging after first translation of basic block starting at rip");
  add(log_on_console,               "consolelog",           "Replicate log file messages to console");
  add(log_ptlsim_boot,              "bootlog",              "Log PTLsim early boot and injection process (for debugging)");
  add(log_buffer_size,              "logbufsize",           "Size of PTLsim logfile buffer (not related to -ringbuf)");
  add(dump_state_now,               "dump-state-now",       "Dump the event log ring buffer and internal state of the active core");
  add(abort_at_end,                 "abort-at-end",         "Abort current simulation after next command (don't wait for next x86 boundary)");
  add(mm_logfile,                   "mm-logfile",           "Log PTLsim memory manager requests (alloc, free) to this file (use with ptlmmlog)");
  add(mm_log_buffer_size,           "mm-logbuf-size",       "Size of PTLsim memory manager log buffer (in events, not bytes)");
  add(enable_inline_mm_logging,     "mm-log-inline",        "Print every memory manager request in the main log file");
  add(enable_mm_validate,           "mm-validate",          "Validate every memory manager request against internal structures (slow)");

  section("Event Ring Buffer Logging Control");
  add(event_log_enabled,            "ringbuf",              "Log all core events to the ring buffer for backwards-in-time debugging");
  add(event_log_ring_buffer_size,   "ringbuf-size",         "Core event log ring buffer size: only save last <ringbuf> entries");
  add(flush_event_log_every_cycle,  "flush-events",         "Flush event log ring buffer to logfile after every cycle");
  add(log_backwards_from_trigger_rip,"ringbuf-trigger-rip", "Print event ring buffer when first uop in this rip is committed");

#ifndef PTLSIM_HYPERVISOR
  // Userspace only
  section("Start Point");
  add(start_at_rip,                 "startrip",             "Start at rip <startrip>");
  add(include_dyn_linker,           "excludeld",            "Exclude dynamic linker execution");
  add(trigger_mode,                 "trigger",              "Trigger mode: wait for user process to do simcall before entering PTL mode");
  add(pause_at_startup,             "pause-at-startup",     "Pause for N seconds after starting up (to allow debugger to attach)");
#endif

  section("Trace Stop Point");
  add(stop_at_user_insns,           "stopinsns",            "Stop after executing <stopinsns> user instructions");
  add(stop_at_iteration,            "stopiter",             "Stop after <stop> iterations (does not apply to cycle-accurate cores)");
  add(stop_at_rip,                  "stoprip",              "Stop before rip <stoprip> is translated for the first time");

#ifdef PTLSIM_HYPERVISOR
  // Full system only
  section("Event Trace Recording");
  add(event_trace_record_filename,  "event-record",         "Save replayable events (interrupts, DMAs, etc) to this file");
  add(event_trace_record_stop,      "event-record-stop",    "Stop recording events");
  add(event_trace_replay_filename,  "event-replay",         "Replay events (interrupts, DMAs, etc) to this file, starting at checkpoint");

  section("Timers and Interrupts");
  add(core_freq_hz,                 "corefreq",             "Core clock frequency in Hz (default uses host system frequency)");
  add(timer_interrupt_freq_hz,      "timerfreq",            "Timer interrupt frequency in Hz");
  add(pseudo_real_time_clock,       "pseudo-rtc",           "Real time clock always starts at time saved in checkpoint");
  add(realtime,                     "realtime",             "Operate in real time: no time dilation (not accurate for I/O intensive workloads!)");
  add(mask_interrupts,              "maskints",             "Mask all interrupts (required for guaranteed deterministic behavior)");
  add(console_mfn,                  "console-mfn",          "Track the specified Xen console MFN");
  add(pause,                        "pause",                "Pause domain after using -native");
  add(perfctr_name,                 "perfctr",              "Performance counter generic name for hardware profiling during native mode");
  add(force_native,                 "force-native",         "Force native mode: ignore attempts to switch to simulation");
#endif

  section("Out of Order Core (ooocore)");
  add(perfect_cache,                "perfect-cache",        "Perfect cache performance: all loads and stores hit in L1");

  section("Miscellaneous");
  add(bbcache_dump_filename,        "bbdump",               "Basic block cache dump filename");
#ifndef PTLSIM_HYPERVISOR
  // Userspace only
  add(sequential_mode_insns,        "seq",                  "Run in sequential mode for <seq> instructions before switching to out of order");
  add(exit_after_fullsim,           "exitend",              "Kill the thread after full simulation completes rather than going native");
#endif
};

#ifndef CONFIG_ONLY

ostream& operator <<(ostream& os, const PTLsimConfig& config) {
  return configparser.print(os, config);
}

void print_banner(ostream& os, const PTLsimStats& stats, int argc, char** argv) {
  utsname hostinfo;
  sys_uname(&hostinfo);

  os << "//  ", endl;
#ifdef __x86_64__
#ifdef PTLSIM_HYPERVISOR
  os << "//  PTLsim: Cycle Accurate x86-64 Full System SMP/SMT Simulator", endl;
#else
  os << "//  PTLsim: Cycle Accurate x86-64 Simulator", endl;
#endif
#else
  os << "//  PTLsim: Cycle Accurate x86 Simulator (32-bit version)", endl;
#endif
  os << "//  Copyright 1999-2007 Matt T. Yourst <yourst@yourst.com>", endl;
  os << "// ", endl;
  os << "//  Revision ", stringify(SVNREV), " (", stringify(SVNDATE), ")", endl;
  os << "//  Built ", __DATE__, " ", __TIME__, " on ", stringify(BUILDHOST), " using gcc-",
    stringify(__GNUC__), ".", stringify(__GNUC_MINOR__), endl;
  os << "//  Running on ", hostinfo.nodename, ".", hostinfo.domainname, endl;
  os << "//  ", endl;
#ifndef PTLSIM_HYPERVISOR
  os << "//  Arguments: ";
  foreach (i, argc) {
    os << argv[i];
    if (i != (argc-1)) os << ' ';
  }
  os << endl;
#endif
  os << endl;
  os << flush;
}

void collect_common_sysinfo(PTLsimStats& stats) {
  utsname hostinfo;
  sys_uname(&hostinfo);

  stringbuf sb;
#define strput(x, y) (strncpy((x), (y), sizeof(x)))

  sb.reset(); sb << __DATE__, " ", __TIME__;
  strput(stats.simulator.version.build_timestamp, sb);
  stats.simulator.version.svn_revision = SVNREV;
  strput(stats.simulator.version.svn_timestamp, stringify(SVNDATE));
  strput(stats.simulator.version.build_hostname, stringify(BUILDHOST));
  sb.reset(); sb << "gcc-", __GNUC__, ".", __GNUC_MINOR__;
  strput(stats.simulator.version.build_compiler, sb);

  stats.simulator.run.timestamp = sys_time(0);
  sb.reset(); sb << hostinfo.nodename, ".", hostinfo.domainname;
  strput(stats.simulator.run.hostname, sb);
  strput(stats.simulator.run.kernel_version, hostinfo.release);
}

void print_usage(int argc, char** argv) {
  cerr << "Syntax: ptlsim <executable> <arguments...>", endl;
  cerr << "All other options come from file /home/<username>/.ptlsim/path/to/executable", endl, endl;

  configparser.printusage(cerr, config);
}

stringbuf current_stats_filename;
stringbuf current_log_filename;
stringbuf current_bbcache_dump_filename;

void backup_and_reopen_logfile() {
  if (config.log_filename) {
    if (logfile) logfile.close();
    stringbuf oldname;
    oldname << config.log_filename, ".backup";
    sys_unlink(oldname);
    sys_rename(config.log_filename, oldname);
    logfile.open(config.log_filename);
  }
}

void force_logging_enabled() {
  logenable = 1;
  config.start_log_at_iteration = 0;
  config.loglevel = 99;
  config.flush_event_log_every_cycle = 1;
}

void print_sysinfo(ostream& os);

bool handle_config_change(PTLsimConfig& config, int argc, char** argv) {
  static bool first_time = true;

  if (config.log_filename.set() && (config.log_filename != current_log_filename)) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    backup_and_reopen_logfile();
    current_log_filename = config.log_filename;
  }

  logfile.setchain((config.log_on_console) ? &cout : null);

  logfile.setbuf(config.log_buffer_size);

  if ((config.loglevel > 0) & (config.start_log_at_rip == INVALIDRIP) & (config.start_log_at_iteration == infinity)) {
    config.start_log_at_iteration = 0;
  }

  // Force printing every cycle if loglevel >= 6:
  if (config.loglevel >= 6) {
    config.event_log_enabled = 1;
    config.flush_event_log_every_cycle = 1;
  }

  //
  // Fix up parameter defaults:
  //
  if (config.start_log_at_rip != INVALIDRIP) {
    config.start_log_at_iteration = infinity;
    logenable = 0;
  } else if (config.start_log_at_iteration != infinity) {
    config.start_log_at_rip = INVALIDRIP;
    logenable = 0;
  }

  logenable = 1;

  if (config.bbcache_dump_filename.set() && (config.bbcache_dump_filename != current_bbcache_dump_filename)) {
    // Can also use "-logfile /dev/fd/1" to send to stdout (or /dev/fd/2 for stderr):
    bbcache_dump_file.open(config.bbcache_dump_filename);
    current_bbcache_dump_filename = config.bbcache_dump_filename;
  }

#ifdef __x86_64__
  config.start_log_at_rip = signext64(config.start_log_at_rip, 48);
  config.log_backwards_from_trigger_rip = signext64(config.log_backwards_from_trigger_rip, 48);
#ifndef PTLSIM_HYPERVISOR
  config.start_at_rip = signext64(config.start_at_rip, 48);
#endif
  config.stop_at_rip = signext64(config.stop_at_rip, 48);
#endif

  if (first_time) {
    if (!config.quiet) {
#ifndef PTLSIM_HYPERVISOR
      print_banner(cerr, stats, argc, argv);
#endif
      print_sysinfo(cerr);
#ifdef PTLSIM_HYPERVISOR
      if (!(config.run | config.native | config.kill))
        cerr << "PTLsim is now waiting for a command.", endl, flush;
#endif
    }
    print_banner(logfile, stats, argc, argv);
    print_sysinfo(logfile);
    cerr << flush;
    logfile << config;
    logfile.flush();
    first_time = false;
  }

#ifdef PTLSIM_HYPERVISOR
  int total = config.run + config.stop + config.native + config.kill;
  if (total > 1) {
    logfile << "Warning: only one action (from -run, -stop, -native, -kill) can be specified at once", endl, flush;
    cerr << "Warning: only one action (from -run, -stop, -native, -kill) can be specified at once", endl, flush;
  }
#endif

  return true;
}

Hashtable<const char*, PTLsimMachine*, 1>* machinetable = null;

// Make sure the vtable gets compiled:
PTLsimMachine dummymachine;

bool PTLsimMachine::init(PTLsimConfig& config) { return false; }
int PTLsimMachine::run(PTLsimConfig& config) { return 0; }
void PTLsimMachine::reset() {
  bbcache.reset();
  initialized = 0;
}
void PTLsimMachine::update_stats(PTLsimStats& stats) { return; }
void PTLsimMachine::dump_state(ostream& os) { return; }
void PTLsimMachine::flush_tlb(Context& ctx) { return; }
void PTLsimMachine::flush_tlb_virt(Context& ctx, Waddr virtaddr) { return; }

void PTLsimMachine::addmachine(const char* name, PTLsimMachine* machine) {
  if unlikely (!machinetable) {
    machinetable = new Hashtable<const char*, PTLsimMachine*, 1>();
  }
  machinetable->add(name, machine);
}

PTLsimMachine* PTLsimMachine::getmachine(const char* name) {
  if unlikely (!machinetable) return null;
  PTLsimMachine** p = machinetable->get(name);
  if (!p) return null;
  return *p;
}

// Currently executing machine model:
PTLsimMachine* current_machine = null;

PTLsimMachine* PTLsimMachine::getcurrent() {
  return current_machine;
}


void simulateInitializedMachine(PTLsimMachine& machine) {
  W64 tsc_at_start = rdtsc();
  current_machine = &machine;
  machine.run(config);
  W64 tsc_at_end = rdtsc();
  machine.update_stats(stats);
  current_machine = null;
}

bool ensureMachineInitialized(PTLsimMachine& m, const char* machinename) {
  if (!m.initialized) {
    logfile << "Initializing core '", machinename, "'", endl;
    if (!m.init(config)) {
      return 1;
    }
    m.initialized = 1;
  }
  return 0;
}

bool simulate(const char* machinename) {
  PTLsimMachine* machine = PTLsimMachine::getmachine(machinename);

  if (!machine) {
    logfile << "Cannot find core named '", machinename, "'", endl;
    cerr << "Cannot find core named '", machinename, "'", endl;
    return 0;
  }

  if (ensureMachineInitialized(*machine, machinename)) {
    logfile << "Cannot initialize core model; check its configuration!", endl;
    return 0;
  }

  logfile << "Switching to simulation core '", machinename, "'...", endl, flush;
  cerr <<  "Switching to simulation core '", machinename, "'...", endl, flush;
  logfile << "Stopping after ", config.stop_at_user_insns, " commits", endl, flush;
  cerr << "Stopping after ", config.stop_at_user_insns, " commits", endl, flush;

  simulateInitializedMachine(*machine);

  stringbuf sb;
  sb << endl, "Stopped after ", sim_cycle, " cycles, ", total_user_insns_committed, " instructions", endl;

  logfile << sb, flush;
  cerr << sb, flush;

  return 0;
}

extern void shutdown_uops();

void shutdown_subsystems() {
  //
  // Let the subsystems close any special files or buffers
  // they may have open:
  //
  shutdown_uops();
  shutdown_decode();
}

#endif // CONFIG_ONLY
