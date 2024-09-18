#include <raspsim-hwsetup.h>
#include <addrspace.h>
#include <ptlsim.h>

struct PTLsimConfig;
extern PTLsimConfig config;

static Context ctx alignto(4096) insection(".ctx"){};
static AddressSpace asp{};

// Raspsim class implementation

Raspsim::Raspsim() {
  config.reset();

  init_uops();
// Set up initial context:
  ctx.reset();
  asp.reset();
  ctx.use32 = 1;
  ctx.use64 = 1;
  ctx.commitarf[REG_rsp] = 0;
  ctx.commitarf[REG_rip] = 0x100000;
  ctx.commitarf[REG_flags] = 0;
  ctx.internal_eflags = 0;

  ctx.seg[SEGID_CS].selector = 0x33;
  ctx.seg[SEGID_SS].selector = 0x2b;
  ctx.seg[SEGID_DS].selector = 0x00;
  ctx.seg[SEGID_ES].selector = 0x00;
  ctx.seg[SEGID_FS].selector = 0x00;
  ctx.seg[SEGID_GS].selector = 0x00;
  ctx.update_shadow_segment_descriptors();

  // ctx.fxrstor(x87state);

  ctx.vcpuid = 0;
  ctx.running = 1;
  ctx.commitarf[REG_ctx] = (Waddr)&ctx;
  ctx.commitarf[REG_fpstack] = (Waddr)&ctx.fpstack;

  //
  // Swap the FP control registers to the user process version, so FP uopimpls
  // can use the real rounding control bits.
  //
  x86_set_mxcsr(ctx.mxcsr | MXCSR_EXCEPTION_DISABLE_MASK);
}

Raspsim::~Raspsim() {
    ctx.reset();
    asp.reset();

    sim_cycle = 0;
    unhalted_cycle_count = 0;
    iterations = 0;
    total_uops_executed = 0;
    total_uops_committed = 0;
    total_user_insns_committed = 0;
    total_basic_blocks_committed = 0;
}

PTLsimMachine* Raspsim::getMachine() {
  return PTLsimMachine::getmachine(config.core_name);
}

const char* Raspsim::getCoreName() { return config.core_name; }

void Raspsim::setLogfile(const char* filename) {
  config.log_filename = filename;
  backup_and_reopen_logfile();
}

Waddr Raspsim::getPageSize() { return PAGE_SIZE; }

AddressSpace& Raspsim::getAddrspace() { return asp; }

Context& Raspsim::getContext() { return ctx; }

W64 Raspsim::getRegisterValue(int reg) { return ctx.commitarf[reg]; }

byte* Raspsim::mmap(Waddr start, int prot) {
  asp.map(start, getPageSize(), prot);
  return (byte*)asp.page_virt_to_mapped(start);
}

void Raspsim::disableSSE() { ctx.no_sse = 1; }
void Raspsim::disableX87() { ctx.no_x87 = 1; }
void Raspsim::enablePerfectCache() { config.perfect_cache = 1; }
void Raspsim::enableStaticBranchPrediction() { config.static_branchpred = 1; }

int Raspsim::getRegisterIndex(const char* regname) {
  int reg = -1;
  foreach (j, sizeof(arch_reg_names) / sizeof(arch_reg_names[0])) {
    if (!strcmp(regname, arch_reg_names[j])) {
      reg = j; break;
    }
  }
  return reg;
}

byte* Raspsim::getMappedPage(Waddr addr) {
  assert(addr % PAGE_SIZE == 0);
  return (byte*)Raspsim::getAddrspace().page_virt_to_mapped(addr);
}

W64 Raspsim::cycles() { return sim_cycle; }
W64 Raspsim::instructions() { return total_user_insns_committed; }

void Raspsim::setRegisterValue(int reg, W64 value) { ctx.commitarf[reg] = value; }

void Raspsim::stutdown() {
  shutdown_subsystems();
  logfile.flush();
  cerr.flush();
}

void Raspsim::run() {
  simulate(config.core_name);
}

const char* Raspsim::getExceptionName(byte exception) {
  return x86_exception_names[exception];
}

// Begin Virtual Hardware Setup for RASPsim

// Userspace PTLsim only supports one VCPU:
int current_vcpuid() { return 0; }

bool asp_check_exec(void* addr) { return Raspsim::getAddrspace().fastcheck(addr, Raspsim::getAddrspace().execmap); }

bool smc_isdirty(Waddr mfn) { return Raspsim::getAddrspace().isdirty(mfn); }
void smc_setdirty(Waddr mfn) { Raspsim::getAddrspace().setdirty(mfn); }
void smc_cleardirty(Waddr mfn) { Raspsim::getAddrspace().cleardirty(mfn); }

bool check_for_async_sim_break() { return iterations >= config.stop_at_iteration; }

int inject_events() { return 0; }
void print_sysinfo(ostream& os) {}

// Only one VCPU in userspace PTLsim:
Context& contextof(int vcpu) { return Raspsim::getContext(); }

W64 loadphys(Waddr addr) {
  W64& data = *(W64*)addr;
  return data;
}

W64 storemask(Waddr addr, W64 data, byte bytemask) {
  W64& mem = *(W64*)addr;
  mem = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);
  return data;
}

int Context::copy_from_user(void* target, Waddr addr, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi) {
  // logfile << "VMEM: Read from user ", (void*)addr, " (", bytes, ")", endl, flush;

  bool readable;
  bool executable;

  int n = 0;
  pfec = 0;

  ptelo = 0;
  ptehi = 0;

  readable = Raspsim::getAddrspace().fastcheck((byte*)addr, asp.readmap);
  if likely (forexec) executable = asp.fastcheck((byte*)addr, asp.execmap);
  if unlikely ((!readable) | (forexec & !executable)) {
    faultaddr = addr;
    pfec.p = readable;
    pfec.nx = (forexec & (!executable));
    pfec.us = 1;
    return n;
  }

  n = min((Waddr)(4096 - lowbits(addr, 12)), (Waddr)bytes);

  void* mapped_addr = asp.page_virt_to_mapped(addr);
  assert(mapped_addr);
  // logfile << "VMEM: Read ", mapped_addr, " = ", *(W8*)mapped_addr, endl, flush;
  memcpy(target, mapped_addr, n);

  // All the bytes were on the first page
  if likely (n == bytes) return n;

  // Go on to second page, if present
  readable = asp.fastcheck((byte*)(addr + n), asp.readmap);
  if likely (forexec) executable = asp.fastcheck((byte*)(addr + n), asp.execmap);
  if unlikely ((!readable) | (forexec & !executable)) {
    faultaddr = addr + n;
    pfec.p = readable;
    pfec.nx = (forexec & (!executable));
    pfec.us = 1;
    return n;
  }

  memcpy((byte*)target + n, asp.page_virt_to_mapped(addr + n), bytes - n);
  return bytes;
}

int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
  // logfile << "VMEM: Write to user ", (void*)target, " (", bytes, ")", endl, flush;

  pfec = 0;
  bool writable = asp.fastcheck((byte*)target, asp.writemap);
  if unlikely (!writable) {
    faultaddr = target;
    pfec.p = asp.fastcheck((byte*)target, asp.readmap);
    pfec.rw = 1;
    return 0;
  }

  byte* targetlo = (byte*)asp.page_virt_to_mapped(target);
  int nlo = min((Waddr)(4096 - lowbits(target, 12)), (Waddr)bytes);

  smc_setdirty(target >> 12);

  // All the bytes were on the first page
  if likely (nlo == bytes) {
    memcpy(targetlo, source, nlo);
    return bytes;
  }

  // Go on to second page, if present
  writable = asp.fastcheck((byte*)(target + nlo), asp.writemap);
  if unlikely (!writable) {
    faultaddr = target + nlo;
    pfec.p = asp.fastcheck((byte*)(target + nlo), asp.readmap);
    pfec.rw = 1;
    pfec.us = 1;
    return nlo;
  }

  memcpy(asp.page_virt_to_mapped(target + nlo), (byte*)source + nlo, bytes - nlo);
  memcpy(targetlo, source, nlo);

  smc_setdirty((target + nlo) >> 12);

  return bytes;
}

Waddr Context::check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate, Level1PTE& pteused) {
  exception = 0;
  pteupdate = 0;
  pteused = 0;
  pfec = 0;

  if unlikely (lowbits(virtaddr, sizeshift)) {
    exception = EXCEPTION_UnalignedAccess;
    return INVALID_PHYSADDR;
  }

  if unlikely (internal) {
    // Directly mapped to PTL space:
    return virtaddr;
  }

  AddressSpace::spat_t top = (store) ? asp.writemap : asp.readmap;

  if unlikely (!asp.fastcheck(virtaddr, top)) {
    exception = (store) ? EXCEPTION_PageFaultOnWrite : EXCEPTION_PageFaultOnRead;
    pfec.p = asp.fastcheck(virtaddr, asp.readmap);
    pfec.rw = store;
    pfec.us = 1;
    return 0;
  }

  return (Waddr) asp.page_virt_to_mapped(floor(signext64(virtaddr, 48), 8));
}

int Context::write_segreg(unsigned int segid, W16 selector) {
  // Well, we don't want to play with the fire...
  return EXCEPTION_x86_gp_fault;
}

void Context::update_shadow_segment_descriptors() {
  W64 limit = (use64) ? 0xffffffffffffffffULL : 0xffffffffULL;

  SegmentDescriptorCache& cs = seg[SEGID_CS];
  cs.present = 1;
  cs.base = 0;
  cs.limit = limit;

  virt_addr_mask = limit;

  SegmentDescriptorCache& ss = seg[SEGID_SS];
  ss.present = 1;
  ss.base = 0;
  ss.limit = limit;

  SegmentDescriptorCache& ds = seg[SEGID_DS];
  ds.present = 1;
  ds.base = 0;
  ds.limit = limit;

  SegmentDescriptorCache& es = seg[SEGID_ES];
  es.present = 1;
  es.base = 0;
  es.limit = limit;

  SegmentDescriptorCache& fs = seg[SEGID_FS];
  fs.present = 1;
  fs.base = 0;
  fs.limit = limit;

  SegmentDescriptorCache& gs = seg[SEGID_GS];
  gs.present = 1;
  gs.base = 0;
  gs.limit = limit;
}

// In userspace PTLsim, virtual == physical:
// FIXME(AE): software virtual memory
RIPVirtPhys& RIPVirtPhys::update(Context& ctx, int bytes) {
  use64 = ctx.use64;
  kernel = 0;
  df = ((ctx.internal_eflags & FLAG_DF) != 0);
  padlo = 0;
  padhi = 0;
  mfnlo = rip >> 12;
  mfnhi = (rip + (bytes-1)) >> 12;
  return *this;
}


void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
    Raspsim::propagate_x86_exception(exception, errorcode, virtaddr);
}

#ifdef __x86_64__

void handle_syscall_64bit() {
  Raspsim::handle_syscall_64bit();
}

#endif // __x86_64__
  
void handle_syscall_32bit(int semantics) {
  Raspsim::handle_syscall_32bit(semantics);
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  requested_switch_to_native = 1; // exit
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

bool requested_switch_to_native = 0;

