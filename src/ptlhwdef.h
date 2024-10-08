// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Hardware Definitions
//
// Copyright 1999-2008 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _PTLHWDEF_H
#define _PTLHWDEF_H

//
// NOTE: The first part of this file is included by assembly code,
// so do not put any C/C++-specific things here until the label
// __ASM_ONLY__ found below.
//

//
// Flags format: OF -  - - SF ZF - AF wait PF inv CF
//               11 10 9 8 7  6    4  3    2  1   0
//               rc -  - - ra ra - ra -    ra -   rb
//
#define FLAG_CF    0x001     // (1 << 0)
#define FLAG_INV   0x002     // (1 << 1)
#define FLAG_PF    0x004     // (1 << 2)
#define FLAG_WAIT  0x008     // (1 << 3)
#define FLAG_AF    0x010     // (1 << 4)
#define FLAG_ZF    0x040     // (1 << 6)
#define FLAG_SF    0x080     // (1 << 7)
#define FLAG_OF    0x800     // (1 << 11)
#define FLAG_BR_TK 0x8000    // (1 << 15)
#define FLAG_SF_ZF 0x0c0     // (1 << 7) | (1 << 6)
#define FLAG_ZAPS  0x0d4     // 000011010100
#define FLAG_NOT_WAIT_INV (FLAG_ZAPS|FLAG_CF|FLAG_OF) // 00000100011010101: exclude others not in ZAPS/CF/OF

#define COND_o   0
#define COND_no  1
#define COND_c   2
#define COND_nc  3
#define COND_e   4
#define COND_ne  5
#define COND_be  6
#define COND_nbe 7
#define COND_s   8
#define COND_ns  9
#define COND_p   10
#define COND_np  11
#define COND_l   12
#define COND_nl  13
#define COND_le  14
#define COND_nle 15

#define COND_z   COND_e
#define COND_nz  COND_ne

#define COND_ae  COND_nc
#define COND_ge  COND_nl

#define COND_b   COND_c

#define ARCHREG_INT_BASE 0
#define ARCHREG_SSE_BASE 16

#include <registers.def>


#ifndef __ASM_ONLY__
//
// The following definitions are used by C++ code
//

#include <globals.h>
extern W64 sim_cycle;
#include <logic.h>
#include <config.h>

//
// Exceptions:
// These are PTL internal exceptions, NOT x86 exceptions:
//
enum {
  EXCEPTION_NoException = 0,
  EXCEPTION_Propagate,
  EXCEPTION_BranchMispredict,
  EXCEPTION_UnalignedAccess,
  EXCEPTION_PageFaultOnRead,
  EXCEPTION_PageFaultOnWrite,
  EXCEPTION_PageFaultOnExec,
  EXCEPTION_StoreStoreAliasing,
  EXCEPTION_LoadStoreAliasing,
  EXCEPTION_CheckFailed,
  EXCEPTION_SkipBlock,
  EXCEPTION_LFRQFull,
  EXCEPTION_FloatingPoint,
  EXCEPTION_FloatingPointNotAvailable,
  EXCEPTION_DivideOverflow,
  EXCEPTION_InvalidAddr,
  EXCEPTION_COUNT
};

static const int MAX_BB_BYTES = 127;
static const int MAX_BB_X86_INSNS = 60;
static const int MAX_BB_UOPS = 63;
static const int MAX_BB_PER_PAGE = 4096;

static const int MAX_TRANSOPS_PER_USER_INSN = 16;

extern const char* exception_names[EXCEPTION_COUNT];

static inline const char* exception_name(W64 exception) {
  return (exception < EXCEPTION_COUNT) ? exception_names[exception] : "Unknown";
}

//
// Uniquely identifies any translation or basic block, including
// the context in which it was translated: x86-64 instruction set,
// kernel vs user mode, flag values, segmentation assumptions, etc.
//
// Most of this information is only relevant for full system PTLsim/X.
// The userspace PTLsim only needs the RIP, use64, df, etc.
//
struct Context;

struct RIPVirtPhysBase {
  W64 rip;
  W64 mfnlo:36, use64:1, kernel:1, padlo:2, mfnhi:36, df:1, padhi:3;

  // 36 bits + 12 page offset bits = 48 bit physical addresses
  static const Waddr INVALID = 0xfffffffff;

  ostream& print(ostream& os) const;
};

struct RIPVirtPhys: public RIPVirtPhysBase {
  operator W64() const { return rip; }

  RIPVirtPhys() { }
  RIPVirtPhys(W64 rip) { this->rip = rip; }

  RIPVirtPhys(Waddr rip, Waddr mfnlo, Waddr mfnhi, bool use64, bool kernelmode);

  // Update use64, kernelmode, mfnlo and mfnhi by translating rip and (rip + 4095), respectively:
  RIPVirtPhys& update(Context& ctx, int bytes = PAGE_SIZE);

  // Make sure we don't accidentally cast to W64 for comparisons
  bool operator ==(const RIPVirtPhys& b) const {
#ifdef PTLSIM_HYPERVISOR
    const W64* ap = (const W64*)this;
    const W64* bp = (const W64*)&b;

    return ((ap[0] == bp[0]) & (ap[1] == bp[1]));
#else
    return (rip == b.rip);
#endif
  }
};

static inline ostream& operator <<(ostream& os, const RIPVirtPhysBase& rvp) { return rvp.print(os); }
static inline ostream& operator <<(ostream& os, const RIPVirtPhys& rvp) { return rvp.print(os); }

//
// Store Forwarding Register definition
//
// Cleverness alert: FLAG_INV is bit 1 in both regular ALU flags
// AND bit 1 in the lowest byte of SFR.physaddr. This is critical
// to making the synthesized simulator code work efficiently.
//
// REMEMBER: sfr.physaddr is >> 3 so it fits in 45 bits (vs 48).
//
struct SFR {
  W64 data;
  W64 addrvalid:1, invalid:1, datavalid:1, physaddr:45, bytemask:8, tag:8;
  W64 smc_mfn; /* hack to pass along the address for smc_setdirty */
};

stringbuf& operator <<(stringbuf& sb, const SFR& sfr);

inline ostream& operator <<(ostream& os, const SFR& sfr) {
  stringbuf sb;
  sb << sfr;
  return os << sb;
}

struct IssueState {
  union {
    struct {
      W64 rddata;
      W64 addr:48, rdflags:16;
    } reg;

    struct {
      W64 rddata;
      W64 physaddr:48, flags:8, lfrqslot:8;
    } ldreg;

    struct {
      W64 riptaken;
      W64 ripseq;
    } brreg;

    SFR st;
  };
};

ostream& operator <<(ostream& os, const IssueState& ctx);

struct IssueInput {
  W64 ra;
  W64 rb;
  W64 rc;
  W16 raflags;
  W16 rbflags;
  W16 rcflags;
};

typedef W64 UserContext[ARCHREG_COUNT];

ostream& operator <<(ostream& os, const UserContext& ctx);

typedef byte X87Reg[10];

struct X87StatusWord {
  W16 ie:1, de:1, ze:1, oe:1, ue:1, pe:1, sf:1, es:1, c0:1, c1:1, c2:1, tos:3, c3:1, b:1;

  X87StatusWord() { }
  X87StatusWord(const W16& w) { *((W16*)this) = w; }
  operator W16() const { return *((W16*)this); }
};

struct X87ControlWord {
  W16 im:1, dm:1, zm:1, om:1, um:1, pm:1, res1:2, pc:2, rc:2, y:1, res2:3;

  X87ControlWord() { }
  X87ControlWord(const W16& w) { *((W16*)this) = w; }
  operator W16() const { return *((W16*)this); }
};

struct X87State {
  X87ControlWord cw;
  W16 reserved1;
  X87StatusWord sw;
  W16 reserved2;
  W16 tw;
  W16 reserved3;
  W32 eip;
  W16 cs;
  W16 opcode;
  W32 dataoffs;
  W16 ds;
  W16 reserved4;
  X87Reg stack[8];
};

union SSEType {
  double d;
  struct { float lo, hi; } f;
  W64 w64;
  struct { W32 lo, hi; } w32;

  SSEType() { }
  SSEType(W64 w) { w64 = w; }
  operator W64() const { return w64; }
};

struct X87RegPadded {
  X87Reg reg;
  byte pad[6];
} packedstruct;

struct XMMReg {
  W64 lo, hi;
};

struct FXSAVEStruct {
  X87ControlWord cw;
  X87StatusWord sw;
  W16 tw;
  W16 fop;
  union {
    struct {
      W32 eip;
      W16 cs;
      W16 reserved1;
      W32 dp;
      W16 ds;
      W16 reserved2;
    } use32;
    struct {
      W64 rip;
      W64 rdp;
    } use64;
  };
  W32 mxcsr;
  W32 mxcsr_mask;
  X87RegPadded fpregs[8];
  XMMReg xmmregs[16];
};

inline W64 x87_fp_80bit_to_64bit(const X87Reg* x87reg) {
  W64 reg64;
  asm("fldt (%[mem80])\n"
      "fstpl %[mem64]\n"
      : : [mem64] "m" (reg64), [mem80] "r" (x87reg));
  return reg64;
}

inline void x87_fp_64bit_to_80bit(X87Reg* x87reg, W64 reg64) {
  asm("fldl %[mem64]\n"
      "fstpt (%[mem80])\n"
      : : [mem80] "r" (*x87reg), [mem64] "m" (reg64) : "memory");
}

inline void cpu_fsave(X87State& state) {
  asm volatile("fsave %[state]" : [state] "=m" (*&state));
}

inline void cpu_frstor(X87State& state) {
  asm volatile("frstor %[state]" : : [state] "m" (*&state));
}

inline W16 cpu_get_fpcw() {
  W16 fpcw;
  asm volatile("fstcw %[fpcw]" : [fpcw] "=m" (fpcw));
  return fpcw;
}

inline void cpu_set_fpcw(W16 fpcw) {
  asm volatile("fldcw %[fpcw]" : : [fpcw] "m" (fpcw));
}

struct SegmentDescriptor {
	W16 limit0;
	W16 base0;
	W16 base1:8, type:4, s:1, dpl:2, p:1;
	W16 limit:4, avl:1, l:1, d:1, g:1, base2:8;

  SegmentDescriptor() { }
  SegmentDescriptor(W64 rawbits) { *((W64*)this) = rawbits; }
  operator W64() const { return *((W64*)this); }

  void setbase(W64 addr) {
    assert((addr >> 32) == 0); // must use FSBASE and GSBASE MSRs for 64-bit addresses
    base0 = lowbits(addr, 16);
    base1 = bits(addr, 16, 8);
    base2 = bits(addr, 24, 8);
  }

  W64 getbase() const {
    return base0 + (base1 << 16) + (base2 << 24);
  }

  void setlimit(W64 size) {
    g = (size >= (1 << 20));
    if likely (g) size = ceil(size, 4096) >> 12;
    limit0 = lowbits(size, 16);
    limit = bits(size, 16, 4);
  }

  W64 getlimit() const {
    W64 size = limit0 + (limit << 16);
    if likely (g) size <<= 12;
    return size;
  }
} packedstruct;

// Encoding of segment numbers:
enum { SEGID_ES = 0, SEGID_CS = 1, SEGID_SS = 2, SEGID_DS = 3, SEGID_FS = 4, SEGID_GS = 5, SEGID_COUNT = 6 };

ostream& operator <<(ostream& os, const SegmentDescriptor& seg);

struct SegmentDescriptorCache {
  W32 selector;
  W32 present:1, use64:1, use32:1, supervisor:1, dpl:2;
  W64 base;
  W64 limit;

  SegmentDescriptorCache() { }

  // NOTE: selector field must be valid already; it is not updated!
  SegmentDescriptorCache& operator =(const SegmentDescriptor& desc) {
    present = desc.p;
    use64 = desc.l;
    use32 = desc.d;
    supervisor = desc.s;
    dpl = desc.dpl;
    base = desc.getbase();
    limit = desc.getlimit();

    return *this;
  }

  // Make 64-bit flat
  void flatten() {
    present = 1;
    use64 = 1;
    use32 = 0;
    supervisor = 0;
    dpl = 3;
    base = 0;
    limit = 0xffffffffffffffffULL;
  }
};

stringbuf& operator <<(stringbuf& os, const SegmentDescriptorCache& seg);
inline ostream& operator <<(ostream& os, const SegmentDescriptorCache& seg) {
  stringbuf sb;
  sb << seg;
  return os << sb;
}

//
// These are x86 exceptions, not PTLsim internal exceptions
//
enum {
  EXCEPTION_x86_divide          = 0,
  EXCEPTION_x86_debug           = 1,
  EXCEPTION_x86_nmi             = 2,
  EXCEPTION_x86_breakpoint      = 3,
  EXCEPTION_x86_overflow        = 4,
  EXCEPTION_x86_bounds          = 5,
  EXCEPTION_x86_invalid_opcode  = 6,
  EXCEPTION_x86_fpu_not_avail   = 7,
  EXCEPTION_x86_double_fault    = 8,
  EXCEPTION_x86_coproc_overrun  = 9,
  EXCEPTION_x86_invalid_tss     = 10,
  EXCEPTION_x86_seg_not_present = 11,
  EXCEPTION_x86_stack_fault     = 12,
  EXCEPTION_x86_gp_fault        = 13,
  EXCEPTION_x86_page_fault      = 14,
  EXCEPTION_x86_spurious_int    = 15,
  EXCEPTION_x86_fpu             = 16,
  EXCEPTION_x86_unaligned       = 17,
  EXCEPTION_x86_machine_check   = 18,
  EXCEPTION_x86_sse             = 19,
  EXCEPTION_x86_count           = 20,
};

extern const char* x86_exception_names[256];

struct PageFaultErrorCode {
  byte p:1, rw:1, us:1, rsv:1, nx:1, pad:3;
  RawDataAccessors(PageFaultErrorCode, byte);
};

ostream& operator <<(ostream& os, const PageFaultErrorCode& pfec);


//
// Information needed to update a PTE on commit.
//
// There is also a ptwrite bit that is set whenever a page
// table page is technically read only, but the user code
// may attempt to store to it anyway under the assumption
// that the hypervisor will trap the store, validate the
// written PTE value and emulate the store as if it was
// to a normal read-write page.
//
struct PTEUpdateBase {
  byte a:1, d:1, ptwrite:1, pad:5;
};

struct PTEUpdate: public PTEUpdateBase {
  RawDataAccessors(PTEUpdate, byte);
};

#ifdef PTLSIM_HYPERVISOR

struct TrapTarget {
#ifdef __x86_64__
  W64 rip:48, cpl:2, maskevents:1, cs:13;
#else
  W32 rip;
  W16 pad;
  W16 cs;
#endif
};

union VirtAddr {
  struct { W64 offset:12, level1:9, level2:9, level3:9, level4:9, signext:16; } lm;
  struct { W64 offset:12, level1:9, level2:9, level3:9, level4:9, signext:16; } pae;
  struct { W32 offset:12, level1:10, level2:10; } x86;

  RawDataAccessors(VirtAddr, W64);
};

#define DefinePTESetField(T, func, field) inline T func(W64 val) const { T pte(*this); pte.field = val; return pte; }

typedef struct Level4PTE {
  W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, mfn:40, avlhi:11, nx:1;
  RawDataAccessors(Level4PTE, W64);

  DefinePTESetField(Level4PTE, P, p);
  DefinePTESetField(Level4PTE, W, rw);
  DefinePTESetField(Level4PTE, U, us);
  DefinePTESetField(Level4PTE, WT, pwt);
  DefinePTESetField(Level4PTE, CD, pcd);
  DefinePTESetField(Level4PTE, A, a);
  DefinePTESetField(Level4PTE, NX, nx);
  DefinePTESetField(Level4PTE, AVL, avl);
  DefinePTESetField(Level4PTE, MFN, mfn);
};

struct Level3PTE {
  W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, mfn:40, avlhi:11, nx:1;
  RawDataAccessors(Level3PTE, W64);

  DefinePTESetField(Level3PTE, P, p);
  DefinePTESetField(Level3PTE, W, rw);
  DefinePTESetField(Level3PTE, U, us);
  DefinePTESetField(Level3PTE, WT, pwt);
  DefinePTESetField(Level3PTE, CD, pcd);
  DefinePTESetField(Level3PTE, A, a);
  DefinePTESetField(Level3PTE, NX, nx);
  DefinePTESetField(Level3PTE, AVL, avl);
  DefinePTESetField(Level3PTE, MFN, mfn);
};

struct Level2PTE {
  W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, d:1, psz:1, mbz:1, avl:3, mfn:40, avlhi:11, nx:1;
  RawDataAccessors(Level2PTE, W64);

  DefinePTESetField(Level2PTE, P, p);
  DefinePTESetField(Level2PTE, W, rw);
  DefinePTESetField(Level2PTE, U, us);
  DefinePTESetField(Level2PTE, WT, pwt);
  DefinePTESetField(Level2PTE, CD, pcd);
  DefinePTESetField(Level2PTE, A, a);
  DefinePTESetField(Level2PTE, D, d);
  DefinePTESetField(Level2PTE, PSZ, psz);
  DefinePTESetField(Level2PTE, NX, nx);
  DefinePTESetField(Level2PTE, AVL, avl);
  DefinePTESetField(Level2PTE, MFN, mfn);
};

struct Level1PTE {
  W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, d:1, pat:1, g:1, avl:3, mfn:40, avlhi:11, nx:1;
  RawDataAccessors(Level1PTE, W64);

  void accum(const Level1PTE& l) { p &= l.p; rw &= l.rw; us &= l.us; nx |= l.nx; }
  void accum(const Level2PTE& l) { p &= l.p; rw &= l.rw; us &= l.us; nx |= l.nx; }
  void accum(const Level3PTE& l) { p &= l.p; rw &= l.rw; us &= l.us; nx |= l.nx; }
  void accum(const Level4PTE& l) { p &= l.p; rw &= l.rw; us &= l.us; nx |= l.nx; }

  DefinePTESetField(Level1PTE, P, p);
  DefinePTESetField(Level1PTE, W, rw);
  DefinePTESetField(Level1PTE, U, us);
  DefinePTESetField(Level1PTE, WT, pwt);
  DefinePTESetField(Level1PTE, CD, pcd);
  DefinePTESetField(Level1PTE, A, a);
  DefinePTESetField(Level1PTE, D, d);
  DefinePTESetField(Level1PTE, G, g);
  DefinePTESetField(Level1PTE, NX, nx);
  DefinePTESetField(Level1PTE, AVL, avl);
  DefinePTESetField(Level1PTE, MFN, mfn);
};

ostream& operator <<(ostream& os, const Level1PTE& pte);
ostream& operator <<(ostream& os, const Level2PTE& pte);
ostream& operator <<(ostream& os, const Level3PTE& pte);
ostream& operator <<(ostream& os, const Level4PTE& pte);

#define X86_CR0_PE              0x00000001 // Enable Protected Mode    (RW)
#define X86_CR0_MP              0x00000002 // Monitor Coprocessor      (RW)
#define X86_CR0_EM              0x00000004 // Require FPU Emulation    (RO)
#define X86_CR0_TS              0x00000008 // Task Switched            (RW)
#define X86_CR0_ET              0x00000010 // Extension type           (RO)
#define X86_CR0_NE              0x00000020 // Numeric Error Reporting  (RW)
#define X86_CR0_WP              0x00010000 // Supervisor Write Protect (RW)
#define X86_CR0_AM              0x00040000 // Alignment Checking       (RW)
#define X86_CR0_NW              0x20000000 // Not Write-Through        (RW)
#define X86_CR0_CD              0x40000000 // Cache Disable            (RW)
#define X86_CR0_PG              0x80000000 // Paging                   (RW)

struct CR0 {
  W64 pe:1, mp:1, em:1, ts:1, et:1, ne:1, res6:10, wp:1, res17:1, am:1, res19:10, nw:1, cd:1, pg:1, res32:32;
  RawDataAccessors(CR0, W64);
};

ostream& operator <<(ostream& os, const CR0& cr0);
// CR2 is page fault linear address

// CR3 is page table physical base

#define X86_CR4_VME		0x0001	// enable vm86 extensions
#define X86_CR4_PVI		0x0002	// virtual interrupts flag enable
#define X86_CR4_TSD		0x0004	// disable time stamp at ipl 3
#define X86_CR4_DE		0x0008	// enable debugging extensions
#define X86_CR4_PSE		0x0010	// enable page size extensions
#define X86_CR4_PAE		0x0020	// enable physical address extensions
#define X86_CR4_MCE		0x0040	// Machine check enable
#define X86_CR4_PGE		0x0080	// enable global pages
#define X86_CR4_PCE		0x0100	// enable performance counters at ipl 3
#define X86_CR4_OSFXSR		0x0200	// enable fast FPU save and restore
#define X86_CR4_OSXMMEXCPT	0x0400	// enable unmasked SSE exceptions
#define X86_CR4_VMXE		0x2000  // enable VMX

struct CR4 {
  W64 vme:1, pvi:1, tsd:1, de:1, pse:1, pae:1, mce:1, pge:1, pce:1, osfxsr:1, osxmmexcpt:1, res11:53;
  RawDataAccessors(CR4, W64);
};

ostream& operator <<(ostream& os, const CR4& cr4);

struct DebugReg {
  W64 l0:1, g0:1, l1:1, g1:1, l2:1, g2:1, l3:1, g3:1, le:1, ge:1, res1:3, gd:1, res2:2,
      t0:2, s0:2, t1:2, s1:2, t2:2, s2:2, t3:2, s3:2;
  RawDataAccessors(DebugReg, W64);
};

enum {
  DEBUGREG_TYPE_EXEC = 0,
  DEBUGREG_TYPE_WRITE = 1,
  DEBUGREG_TYPE_IO = 2,
  DEBUGREG_TYPE_RW = 3,
};

enum {
  DEBUGREG_SIZE_1 = 0,
  DEBUGREG_SIZE_2 = 1,
  DEBUGREG_SIZE_8 = 2,
  DEBUGREG_SIZE_4 = 3,
};

// Extended Feature Enable Register
struct EFER {
  W32 sce:1, pad1:7, lme:1, pad2:1, lma:1, nxe:1, svme:1, pad3:1, ffxsr:1, pad4:17;
  RawDataAccessors(EFER, W32);
};

struct vcpu_guest_context;
struct vcpu_extended_context;

Level1PTE page_table_walk(W64 rawvirt, W64 toplevel_mfn, bool do_special_translations = true);
void page_table_acc_dirty_update(W64 rawvirt, W64 toplevel_mfn, const PTEUpdate& update);
W64 host_mfn_to_sim_mfn(W64 hostmfn);
W64 sim_mfn_to_host_mfn(W64 simmfn);

//
// This is the same format as Xen's vcpu_runstate_info_t
// but solves some header file problems by placing it here.
//
struct RunstateInfo {
  // VCPU's current state (RUNSTATE_*).
  int state;
  // When was current state entered (system time, ns)?
  W64 state_entry_time;
  //
  // Time spent in each RUNSTATE_* (ns). The sum of these times is
  // guaranteed not to drift from system time.
  //
  W64 time[4];
};

#else

// Dummy type for usermode
typedef W64 Level1PTE;

#endif

//
// This is the complete x86 user-visible context for a single VCPU.
// It includes both the renamable registers (commitarf) as well as
// all relevant control registers, MSRs, x87 FP state, exception
// and interrupt vectors, Xen-specific data and so forth.
//
// The ContextBase structure must be less than 4096 bytes (1 page);
// the actual Context structure rounds the size up to a page
//
// PTLsim cores will need to define other per-VCPU structures to
// hold their internal state.
//
struct ContextBase {
  W64 commitarf[64];
  int vcpuid;
  SegmentDescriptorCache seg[SEGID_COUNT];
  W64 swapgs_base;

  W64 fpstack[8];
  X87ControlWord fpcw;
  MXCSR mxcsr;

  byte use32; // depends on active CS descriptor
  byte use64; // depends on active CS descriptor

  Waddr virt_addr_mask;
  W64 exception;
  Waddr error_code;

  W32 internal_eflags; // parts of EFLAGS that are infrequently updated

#ifdef PTLSIM_HYPERVISOR
  Waddr x86_exception;

  byte kernel_mode; // VGCF_IN_KERNEL
  byte kernel_in_syscall; // VGCF_IN_SYSCALL
  byte i387_valid; // VGCF_I387_VALID
  byte failsafe_disables_events;
  byte syscall_disables_events;
  byte saved_upcall_mask;
  byte running;
  byte dirty; // VCPU was just brought online

  CR0 cr0;
  Waddr cr1, cr2, cr3;
  CR4 cr4;
  Waddr cr5, cr6, cr7;
  Waddr kernel_ptbase_mfn, user_ptbase_mfn;
  DebugReg dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7;
  Waddr kernel_ss, kernel_sp;

  Waddr event_callback_rip;
  Waddr failsafe_callback_rip;
  Waddr syscall_rip;

  Waddr fs_base;
  Waddr gs_base_kernel;
  Waddr gs_base_user;
  EFER efer;

  struct TrapTarget idt[256]; // Virtual IDT
  Waddr ldtvirt;
  Waddr gdtpages[16];
  W16 ldtsize;
  W16 gdtsize;

  Waddr vm_assist;

  W64 base_tsc;
  W64 base_system_time;
  W64 core_freq_hz;
  double sys_time_cycles_to_nsec_coeff;

  W16s virq_to_port[32];
  W64  timer_cycle;
  W64  poll_timer_cycle;

  RunstateInfo runstate;
  RunstateInfo* user_runstate;

  static const int PTE_CACHE_SIZE = 16;
  W64 cached_pte_virt[PTE_CACHE_SIZE];
  Level1PTE cached_pte[PTE_CACHE_SIZE];
#else
  // Always running in userspace version:
  byte running;

  Waddr x86_exception;
  Waddr cr2;

  byte no_x87, no_sse;
#endif

  inline void reset() {
    setzero(commitarf);
#ifdef PTLSIM_HYPERVISOR
    setzero(cached_pte_virt);
    setzero(cached_pte);
#endif

    exception = 0;
  }
};

// Round up to a full page:
struct Context: public ContextBase {
  byte padding[PAGE_SIZE - sizeof(ContextBase)];

  void propagate_x86_exception(byte exception, W32 errorcode = 0, Waddr virtaddr = 0);

  Waddr check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate, Level1PTE& pteused);

  Waddr check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate) {
    Level1PTE dummy;
    return check_and_translate(virtaddr, sizeshift, store, internal, exception, pfec, pteupdate, dummy);
  }

  int copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr);

  int copy_from_user(void* target, Waddr source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi);

  int copy_from_user(void* target, Waddr source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec = false) {
    Level1PTE ptelo;
    Level1PTE ptehi;
    return copy_from_user(target, source, bytes, pfec, faultaddr, forexec, ptelo, ptehi);
  }

  int copy_from_user(void* target, Waddr source, int bytes) {
    PageFaultErrorCode pfec;
    Waddr faultaddr;
    return copy_from_user(target, source, bytes, pfec, faultaddr, false);
  }

  int copy_to_user(Waddr target, void* source, int bytes) {
    PageFaultErrorCode pfec;
    Waddr faultaddr;
    return copy_to_user(target, source, bytes, pfec, faultaddr);
  }

  int write_segreg(unsigned int segid, W16 selector);
  void reload_segment_descriptor(unsigned int segid, W16 selector);
  void swapgs();
  void init();
  void fxsave(FXSAVEStruct& state);
  void fxrstor(const FXSAVEStruct& state);

  Context() { }

#ifdef PTLSIM_HYPERVISOR
  void restorefrom(const vcpu_guest_context& ctx);
  void restorefrom(const vcpu_extended_context& ctx);
  void saveto(vcpu_guest_context& ctx);
  void saveto(vcpu_extended_context& ctx);

  bool gdt_entry_valid(W16 idx);
  SegmentDescriptor get_gdt_entry(W16 idx);

#ifndef PTLSIM_PUBLIC_ONLY
  Level1PTE virt_to_host_pte(W64 rawvirt);
  Level1PTE virt_to_pte(W64 rawvirt);
#endif

  W64 virt_to_pte_phys_addr(Waddr virtaddr, int level = 0);

  int virt_to_pte_span(Level1PTE* ptes, W64 virtaddr, int pagecount);

  // Flush the context mini-TLB and propagate flush to any core-specific TLBs
  void flush_tlb(bool propagate_flush_to_model = true);
  void flush_tlb_virt(Waddr virtaddr, bool propagate_flush_to_model = true);
  void print_tlb(ostream& os);

  void update_pte_acc_dirty(W64 rawvirt, const PTEUpdate& update) {
    return page_table_acc_dirty_update(rawvirt, cr3 >> 12, update);
  }

  bool create_bounce_frame(W16 target_cs, Waddr target_rip, int action);

  bool check_events() const;
  bool event_upcall();
  bool change_runstate(int newstate);

  int page_table_level_count() const { return 4; }
#else
  void update_pte_acc_dirty(W64 rawvirt, const PTEUpdate& update) { }
  void update_shadow_segment_descriptors();
#endif
};

stringbuf& operator <<(stringbuf& os, const Context& ctx);

static inline ostream& operator <<(ostream& os, const Context& ctx) {
  stringbuf sb;
  sb << ctx;
  return os << sb;
}

// Other flags not defined above
enum {
  FLAG_TF = (1 << 8),
  FLAG_IF = (1 << 9),
  FLAG_DF = (1 << 10),
  FLAG_IOPL = (1 << 12) | (1 << 13),
  FLAG_NT = (1 << 14),
  FLAG_RF = (1 << 16),
  FLAG_VM = (1 << 17),
  FLAG_AC = (1 << 18),
  FLAG_VIF = (1 << 19),
  FLAG_VIP = (1 << 20),
  FLAG_ID = (1 << 21),
  FLAG_COUNT = 22,
};

//
// Operation Classes
//

#define OPCLASS_LOGIC                   (1 << 0)

#define OPCLASS_ADDSUB                  (1 << 1)
#define OPCLASS_ADDSUBC                 (1 << 2)
#define OPCLASS_ADDSHIFT                (1 << 3)
#define OPCLASS_ADD                     (OPCLASS_ADDSUB|OPCLASS_ADDSUBC|OPCLASS_ADDSHIFT)

#define OPCLASS_SELECT                  (1 << 4)
#define OPCLASS_COMPARE                 (1 << 5)
#define OPCLASS_COND_BRANCH             (1 << 6)

#define OPCLASS_INDIR_BRANCH            (1 << 7)
#define OPCLASS_UNCOND_BRANCH           (1 << 8)
#define OPCLASS_ASSIST                  (1 << 9)
#define OPCLASS_BARRIER                 (OPCLASS_ASSIST)
#define OPCLASS_BRANCH                  (OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH|OPCLASS_UNCOND_BRANCH|OPCLASS_ASSIST)

#define OPCLASS_LOAD                    (1 << 11)
#define OPCLASS_STORE                   (1 << 12)
#define OPCLASS_PREFETCH                (1 << 13)
#define OPCLASS_FENCE                   ((1 << 10) | OPCLASS_STORE)
#define OPCLASS_MEM                     (OPCLASS_LOAD|OPCLASS_STORE|OPCLASS_PREFETCH|OPCLASS_FENCE)

#define OPCLASS_SIMPLE_SHIFT            (1 << 14)
#define OPCLASS_SHIFTROT                (1 << 15)
#define OPCLASS_MULTIPLY                (1 << 16)
#define OPCLASS_BITSCAN                 (1 << 17)
#define OPCLASS_FLAGS                   (1 << 18)
#define OPCLASS_CHECK                   (1 << 19)

#define OPCLASS_CONDITIONAL             (OPCLASS_SELECT|OPCLASS_COND_BRANCH|OPCLASS_CHECK)

#define OPCLASS_ALU_SIZE_MERGING        (OPCLASS_LOGIC|OPCLASS_ADD|OPCLASS_SELECT|OPCLASS_SIMPLE_SHIFT|OPCLASS_SHIFTROT|OPCLASS_MULTIPLY|OPCLASS_BITSCAN)

#define OPCLASS_FP_ALU                  (1 << 20)
#define OPCLASS_FP_DIVSQRT              (1 << 21)
#define OPCLASS_FP_COMPARE              (1 << 22)
#define OPCLASS_FP_PERMUTE              (1 << 23)
#define OPCLASS_FP_CONVERTI2F           (1 << 24)
#define OPCLASS_FP_CONVERTF2I           (1 << 25)
#define OPCLASS_FP_CONVERTFP            (1 << 26)

#define OPCLASS_FP                      (OPCLASS_FP_ALU | OPCLASS_FP_DIVSQRT | OPCLASS_FP_COMPARE | OPCLASS_FP_PERMUTE | OPCLASS_FP_CONVERTI2F | OPCLASS_FP_CONVERTF2I, OPCLASS_FP_CONVERTFP)

#define OPCLASS_VEC_ALU                 (1 << 27)

#define OPCLASS_COUNT                   28

#define OPCLASS_USECOND                 (OPCLASS_COND_BRANCH|OPCLASS_SELECT|OPCLASS_CHECK)

extern const char* opclass_names[OPCLASS_COUNT];

//
// Micro-operations (uops):
// See table in ptlhwdef.cpp for details.
//
enum {
  OP_nop,
  OP_mov,
  // Logical
  OP_and,
  OP_andnot,
  OP_xor,
  OP_or,
  OP_nand,
  OP_ornot,
  OP_eqv,
  OP_nor,
  // Mask, insert or extract bytes
  OP_maskb,
  // Add and subtract
  OP_add,
  OP_sub,
  OP_adda,
  OP_suba,
  OP_addm,
  OP_subm,
  // Condition code logical ops
  OP_andcc,
  OP_orcc,
  OP_xorcc,
  OP_ornotcc,
  // Condition code movement and merging
  OP_movccr,
  OP_movrcc,
  OP_collcc,
  // Simple shifting (restricted to small immediate 1..8)
  OP_shls,
  OP_shrs,
  OP_bswap,
  OP_sars,
  // Bit testing
  OP_bt,
  OP_bts,
  OP_btr,
  OP_btc,
  // Set and select
  OP_set,
  OP_set_sub,
  OP_set_and,
  OP_sel,
  OP_sel_cmp,
  // Branches
  OP_br,
  OP_br_sub,
  OP_br_and,
  OP_jmp,
  OP_bru,
  OP_jmpp,
  OP_brp,
  // Checks
  OP_chk,
  OP_chk_sub,
  OP_chk_and,
  // Loads and stores
  OP_ld,
  OP_ldx,
  OP_ld_pre,
  OP_ld_a16,
  OP_st,
  OP_st_a16,
  OP_mf,
  // Shifts, rotates and complex masking
  OP_shl,
  OP_shr,
  OP_mask,
  OP_sar,
  OP_rotl,
  OP_rotr,
  OP_rotcl,
  OP_rotcr,
  // Multiplication
  OP_mull,
  OP_mulh,
  OP_mulhu,
  OP_mulhl,
  // Bit scans
  OP_ctz,
  OP_clz,
  OP_ctpop,
  OP_permb,
  // Integer divide and remainder step
  OP_div,
  OP_rem,
  OP_divs,
  OP_rems,
  // Minimum and maximum
  OP_min,
  OP_max,
  OP_min_s,
  OP_max_s,
  // Floating point
  OP_fadd,
  OP_fsub,
  OP_fmul,
  OP_fmadd,
  OP_fmsub,
  OP_fmsubr,
  OP_fdiv,
  OP_fsqrt,
  OP_frcp,
  OP_frsqrt,
  OP_fmin,
  OP_fmax,
  OP_fcmp,
  OP_fcmpcc,
  OP_fcvt_i2s_ins,
  OP_fcvt_i2s_p,
  OP_fcvt_i2d_lo,
  OP_fcvt_i2d_hi,
  OP_fcvt_q2s_ins,
  OP_fcvt_q2d,
  OP_fcvt_s2i,
  OP_fcvt_s2q,
  OP_fcvt_s2i_p,
  OP_fcvt_d2i,
  OP_fcvt_d2q,
  OP_fcvt_d2i_p,
  OP_fcvt_d2s_ins,
  OP_fcvt_d2s_p,
  OP_fcvt_s2d_lo,
  OP_fcvt_s2d_hi,
  // Vector integer uops
  // size defines element size: 00 = byte, 01 = W16, 10 = W32, 11 = W64 (same as normal ops)
  OP_vadd,
  OP_vsub,
  OP_vadd_us,
  OP_vsub_us,
  OP_vadd_ss,
  OP_vsub_ss,
  OP_vshl,
  OP_vshr,
  OP_vbt, // bit test vector (e.g. pack bit 7 of 8 bytes into 8-bit output, for pmovmskb)
  OP_vsar,
  OP_vavg,
  OP_vcmp,
  OP_vmin,
  OP_vmax,
  OP_vmin_s,
  OP_vmax_s,
  OP_vmull,
  OP_vmulh,
  OP_vmulhu,
  OP_vmaddp,
  OP_vsad,
  OP_vpack_us,
  OP_vpack_ss,
  OP_MAX_OPCODE,
};

// Limit for shls, shrs, sars rb immediate:
#define SIMPLE_SHIFT_LIMIT 8

struct OpcodeInfo {
  const char* name;
  W32 opclass;
  W16 flagops;
};

//
// flagops field encodings:
//
#define makeccbits(b0, b1, b2) ((b0 << 0) + (b1 << 1) + (b2 << 2))
#define ccA   makeccbits(1, 0, 0)
#define ccB   makeccbits(0, 1, 0)
#define ccAB  makeccbits(1, 1, 0)
#define ccABC makeccbits(1, 1, 1)
#define ccC   makeccbits(0, 0, 1)

#define makeopbits(b3, b4, b5) ((b3 << 3) + (b4 << 4) + (b5 << 5))

#define opA   makeopbits(1, 0, 0)
#define opAB  makeopbits(1, 1, 0)
#define opABC makeopbits(1, 1, 1)
#define opB   makeopbits(0, 1, 0)
#define opC   makeopbits(0, 0, 1)

// Size field is not used
#define opNOSIZE (1 << 6)

extern const OpcodeInfo opinfo[OP_MAX_OPCODE];

inline bool isclass(int opcode, W32 opclass) { return ((opinfo[opcode].opclass & opclass) != 0); }
inline int opclassof(int opcode) { return lsbindex(opinfo[opcode].opclass); }

inline bool isload(int opcode) { return isclass(opcode, OPCLASS_LOAD); }
inline bool isprefetch(int opcode) { return isclass(opcode, OPCLASS_PREFETCH); }
inline bool isstore(int opcode) { return isclass(opcode, OPCLASS_STORE); }
inline bool iscondbranch(int opcode) { return isclass(opcode, OPCLASS_COND_BRANCH|OPCLASS_INDIR_BRANCH); }
inline bool isbranch(int opcode) { return isclass(opcode, OPCLASS_BRANCH); }
inline bool isbarrier(int opcode) { return isclass(opcode, OPCLASS_BARRIER); }
inline const char* nameof(int opcode) { return (opcode < OP_MAX_OPCODE) ? opinfo[opcode].name : "INVALID"; }

union MaskControlInfo {
  struct { W32 ms:6, mc:6, ds:6; } info;
  W32 data;

  MaskControlInfo() { }

  MaskControlInfo(W32 data) { this->data = data; }

  MaskControlInfo(int ms, int mc, int ds) {
    this->info.ms = ms;
    this->info.mc = mc;
    this->info.ds = ds;
  }

  operator W32() const { return data; }
};

#define MakePermuteControlInfo(b7, b6, b5, b4, b3, b2, b1, b0) \
  (W32) (b7 << (7*4)) + (b6 << (6*4)) + (b5 << (5*4)) + (b4 << (4*4)) + \
  (b3 << (3*4)) + (b2 << (2*4)) + (b1 << (1*4)) + (b0 << (0*4))

union PermbControlInfo {
  struct { W32 b0:4, b1:4, b2:4, b3:4, b4:4, b5:4, b6:4, b7:4; } info;
  W32 data;

  PermbControlInfo() { }

  PermbControlInfo(W32 data) { this->data = data; }

  PermbControlInfo(int b7, int b6, int b5, int b4, int b3, int b2, int b1, int b0) {
    info.b0 = b0;
    info.b1 = b1;
    info.b2 = b2;
    info.b3 = b3;
    info.b4 = b4;
    info.b5 = b5;
    info.b6 = b6;
    info.b7 = b7;
  }

  operator W32() const { return data; }
};

// Mask uop control
static inline W32 make_mask_control_info(int ms, int mc, int ds) {
  return (ms) | (mc << 6) | (ds << 12);
}

// These go in the extshift field of mf (memory fence) uops:
#define MF_TYPE_SFENCE (1 << 0)
#define MF_TYPE_LFENCE (1 << 1)

// These go in the extshift field of branch and/or jump operations; they are used as hints only:
#define BRANCH_HINT_PUSH_RAS (1 << 0)
#define BRANCH_HINT_POP_RAS (1 << 1)

inline int invert_cond(int cond) {
  // Conveniently, x86 branch conds may be inverted by just flipping bit zero:
  return (cond ^ 1);
}

extern const char* arch_reg_names[TRANSREG_COUNT];

extern const char* cond_code_names[16];

/*
 * Convert a condition code (as in jump, setcc, cmovcc, etc) to
 * the one or two architectural registers last updated with the
 * flags that uop will test.
 */
struct CondCodeToFlagRegs {
  byte req2, ra, rb;
};

extern const CondCodeToFlagRegs cond_code_to_flag_regs[16];

enum {
  SETFLAG_ZF = (1 << 0),
  SETFLAG_CF = (1 << 1),
  SETFLAG_OF = (1 << 2),
  SETFLAG_COUNT = 3
};

extern const char* setflag_names[SETFLAG_COUNT];
extern const char* x86_flag_names[32];
extern const W16 setflags_to_x86_flags[1<<3];

//
// Structures
//

// This is for profiling purposes only, since all loads and stores are uniform except for their sizes:
enum {
  DATATYPE_INT, DATATYPE_FLOAT, DATATYPE_VEC_FLOAT,
  DATATYPE_DOUBLE, DATATYPE_VEC_DOUBLE,
  DATATYPE_VEC_8BIT, DATATYPE_VEC_16BIT,
  DATATYPE_VEC_32BIT, DATATYPE_VEC_64BIT,
  DATATYPE_VEC_128BIT, DATATYPE_COUNT
};
extern const char* datatype_names[DATATYPE_COUNT];

struct TransOpBase {
  // Opcode:
  byte opcode;
  // Size shift, extshift
  byte size:2, extshift:2, unaligned:1;
  // Condition codes (for loads/stores, cond = alignment)
  byte cond:4, setflags:3, nouserflags:1;
  // Loads and stores:
  byte internal:1, locked:1, cachelevel:2, datatype:4;
  // x86 semantics
  byte bytes:4, som:1, eom:1, is_sse:1, is_x87:1;
  // Operands
  byte rd, ra, rb, rc;
  // Index in basic block
  byte bbindex;
  // Misc info (terminal writer of targets in this insn, etc)
  byte final_insn_in_bb:1, final_arch_in_insn:1, final_flags_in_insn:1, any_flags_in_insn:1, pad:3, marked:1;
  // Immediates
  W64s rbimm;
  W64s rcimm;
  W64 riptaken;
  W64 ripseq;
};

struct TransOp: public TransOpBase {
  TransOp() { }

  TransOp(int opcode, int rd, int ra, int rb, int rc, int size, W64s rbimm = 0, W64s rcimm = 0, W32 setflags = 0, int memid = 0) {
    init(opcode, rd, ra, rb, rc, size, rbimm, rcimm, setflags, memid);
  }

  void init(int opcode, int rd, int ra, int rb, int rc, int size, W64s rbimm = 0, W64s rcimm = 0, W32 setflags = 0, int memid = 0)  {
    setzero(*this);
    this->opcode = opcode;
    this->rd = rd;
    this->ra = ra;
    this->rb = rb;
    this->rc = rc;
    this->size = size;
    this->rbimm = rbimm;
    this->rcimm = rcimm;
    this->setflags = setflags;
  }
};

enum { LDST_ALIGN_NORMAL, LDST_ALIGN_LO, LDST_ALIGN_HI };

ostream& operator <<(ostream& os, const TransOpBase& op);
stringbuf& operator <<(stringbuf& os, const TransOpBase& op);

struct BasicBlock;

typedef void (*uopimpl_func_t)(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags);


//
// List of all BBs on a physical page (for SMC invalidation)
// With 60 (or 62 on 32-bit PTLsim) 32-bit entries per page,
// this comes out to exactly 256 bytes per chunk.
//
#ifdef __x86_64__
#define BB_PTRS_PER_CHUNK 60
#else
#define BB_PTRS_PER_CHUNK 62
#endif

// We don't have this defined outside the PTLsim build process:
#ifdef PTLSIM_PUBLIC_ONLY
#define PTLSIM_VIRT_BASE 0
#endif

#ifdef PTLSIM_HYPERVISOR
typedef shortptr<BasicBlock, W32, PTLSIM_VIRT_BASE> BasicBlockPtr;
#else
#if 0
typedef shortptr<BasicBlock> BasicBlockPtr;
#else
/* the above does weird things and causes a segfault in BasicBlockCache::invalidate_page
 * So turn it into a normal pointer basically
 */
typedef shortptr<BasicBlock, W64> BasicBlockPtr;
#endif
#endif

struct BasicBlockChunkList: public ChunkList<BasicBlockPtr, BB_PTRS_PER_CHUNK> {
  selflistlink hashlink;
  W64 mfn;
  int refcount;

  BasicBlockChunkList(): ChunkList<BasicBlockPtr, BB_PTRS_PER_CHUNK>() { refcount = 0; }
  BasicBlockChunkList(W64 mfn): ChunkList<BasicBlockPtr, BB_PTRS_PER_CHUNK>() { this->mfn = mfn; refcount = 0; }
};

enum { BB_TYPE_COND, BB_TYPE_UNCOND, BB_TYPE_INDIR, BB_TYPE_ASSIST, BB_TYPE_COUNT };
extern const char* bb_type_names[BB_TYPE_COUNT];

//
// Predecode information for basic blocks:
//
// Given the BB start RIP, the BB length in bytes (up to 127)  and the
// branch type (with implied x86 immediate size), we can reconstruct
// the immediate by reading it from the actual x86 code. This allows the
// predecode info storage to be very small.
//
// BranchType:
//   000: bru   imm8
//   001: bru   imm32
//   010: br.cc imm8
//   011: br.cc imm32
//   100: brp          no immediate in x86 code, but this is barrier we cannot cross anyway
//   101: br.split     branch split for overlength BBs: implied offset is zero
//   110: rep          repeated string move (examine opcode prefix bytes to find out which type)
//   111: jmp          indirect jump
//
// Possible x86 instructions:
//
// Direct:
//   7x    imm8      jcc cond
//   0f 8x imm32     jcc cond
//   e3    imm8      jcxz cond
//   eb    imm8      jmp uncond
//   e9    imm32     jmp uncond
//   e8    imm32     call
//   e0    imm8      loopnz
//   e1    imm8      loopz
//   e2    imm8      loop
// Indirect:
//   ff/4            jmp indirect
//   ff/2            call indirect
//   c3              ret indirect
//   c2    imm16     ret indirect with arg count
//
// Far control transfers and other uncommon instructions are considered barriers.
//

enum {
  BRTYPE_BRU_IMM8   = 0,
  BRTYPE_BRU_IMM32  = 1,
  BRTYPE_BR_IMM8    = 2,
  BRTYPE_BR_IMM32   = 3,
  BRTYPE_BARRIER    = 4,
  BRTYPE_SPLIT      = 5,
  BRTYPE_REP        = 6,
  BRTYPE_JMP        = 7
};

static const char* branch_type_names[8] = {
  "bru8",
  "bru32",
  "br8",
  "br32",
  "asist",
  "split",
  "rep",
  "jmp"
};


struct BasicBlockBase {
  RIPVirtPhys rip;
  selflistlink hashlink;
  BasicBlockChunkList::Locator mfnlo_loc;
  BasicBlockChunkList::Locator mfnhi_loc;
  W64 rip_taken;
  W64 rip_not_taken;
  W16 count;
  W16 bytes;
  W16 user_insn_count;
  W16 tagcount;
  W16 memcount;
  W16 storecount;
  byte type:4, repblock:1, invalidblock:1, call:1, ret:1;
  byte marked:1, mfence:1, x87:1, sse:1, nondeterministic:1, brtype:3;
  W64 usedregs;
  uopimpl_func_t* synthops;
  int refcount;
  W32 hitcount;
  W32 predcount;
  W32 confidence;
  W64 lastused;
  W64 lasttarget;

  void acquire() {
    refcount++;
  }

  bool release() {
    refcount--;
    assert(refcount >= 0);
    return (!refcount);
  }
};

struct BasicBlock: public BasicBlockBase {
  TransOp transops[MAX_BB_UOPS*2];

  void reset();
  void reset(const RIPVirtPhys& rip);
  BasicBlock* clone();
  void free();
  void use(W64 counter) { lastused = counter; };
};

ostream& operator <<(ostream& os, const BasicBlock& bb);

//
// Printing and information
//
stringbuf& nameof(stringbuf& sbname, const TransOpBase& uop);

char* regname(int r);

stringbuf& print_value_and_flags(stringbuf& sb, W64 value, W16 flags);

struct flagstring {
  W64 bits;
  int n;
  bool reverse;

  flagstring() { }

  flagstring(const W64 bits) {
    this->bits = bits;
  }
};

static inline ostream& operator <<(ostream& os, const flagstring& bs) {
  for (int i = 31; i >= 0; i--) {
    if (bit(bs.bits, i)) os << x86_flag_names[i];
  }

  return os;
}

static inline stringbuf& operator <<(stringbuf& sb, const flagstring& bs) {
  for (int i = 31; i >= 0; i--) {
    if (bit(bs.bits, i)) sb << x86_flag_names[i];
  }

  return sb;
}

typedef void (*assist_func_t)(Context& ctx);

const char* assist_name(assist_func_t func);
int assist_index(assist_func_t func);


//
// This part is used when parsing stats.h to build the
// data store template; these must be in sync with the
// corresponding definitions elsewhere.
//
#ifdef DSTBUILD
static const char* sizeshift_names[4] = {
  "1 (byte)", "2 (word)", "4 (dword)", "8 (qword)"
};
#endif
#endif // __ASM_ONLY__
#endif // _PTLHWDEF_H
