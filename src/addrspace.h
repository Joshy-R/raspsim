// -*- c++ -*-
//
// Branch Prediction
//
// Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
// TODO: change to alexis

#ifndef _ADDRSPACE_H_
#define _ADDRSPACE_H_

#include <globals.h>
#include <superstl.h>

#include <ptlsim.h>

//
// Address space management
//

#ifdef __x86_64__

// Each chunk covers 2 GB of virtual address space:
#define SPAT_TOPLEVEL_CHUNK_BITS 17
#define SPAT_PAGES_PER_CHUNK_BITS 19
#define SPAT_TOPLEVEL_CHUNKS (1 << SPAT_TOPLEVEL_CHUNK_BITS) // 262144
#define SPAT_PAGES_PER_CHUNK (1 << SPAT_PAGES_PER_CHUNK_BITS) // 524288
#define SPAT_BYTES_PER_CHUNK (SPAT_PAGES_PER_CHUNK / 8)    // 65536
#define ADDRESS_SPACE_BITS (48)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)

#else

// Each chunk covers 2 GB of virtual address space:
#define ADDRESS_SPACE_BITS (32)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)
#define SPAT_BYTES ((ADDRESS_SPACE_SIZE / PAGE_SIZE) / 8)

#endif

class AddressSpace {
public:
  AddressSpace()  { }
  ~AddressSpace()  { }
  void reset();
public:
  Hashtable<Waddr, W8*> mapped_mem;

  void map(Waddr start, Waddr length, int prot) {
    start = floor(start, PAGE_SIZE);
    length = ceil(length, PAGE_SIZE);
    Waddr num_pages = length / PAGE_SIZE;
    foreach (i, num_pages) {
      W8* old_val;
      if (mapped_mem.remove(start + i * PAGE_SIZE, old_val))
        delete[] old_val;
      mapped_mem.add(start + i * PAGE_SIZE, new W8[PAGE_SIZE]());
    }
    setattr((byte*)start, length, prot);
  }
  void unmap(Waddr start, Waddr length) {
    start = floor(start, PAGE_SIZE);
    length = ceil(length, PAGE_SIZE);
    Waddr num_pages = length / PAGE_SIZE;
    foreach (i, num_pages) {
      W8* old_val;
      if (mapped_mem.remove(start + i * PAGE_SIZE, old_val))
        delete[] old_val;
    }
    setattr((byte*)start, length, PROT_NONE);
  }

  void* page_virt_to_mapped(Waddr addr) {
    W8** res = mapped_mem.get(floor(addr, PAGE_SIZE));
    if (!res) return res;
    return (W8*)*res + lowbits(addr, 12);
  }

  //
  // Shadow page attribute table
  //
#ifdef __x86_64__
  typedef byte SPATChunk[SPAT_BYTES_PER_CHUNK];
  typedef SPATChunk** spat_t;
#else
  typedef byte* spat_t;
#endif
  spat_t readmap;
  spat_t writemap;
  spat_t execmap;
  spat_t dirtymap;

  spat_t allocmap();
  void freemap(spat_t top);

  byte& pageid_to_map_byte(spat_t top, Waddr pageid);
  void make_accessible(void* address, Waddr size, spat_t top);
  void make_inaccessible(void* address, Waddr size, spat_t top);

  Waddr pageid(void* address) const {
#ifdef __x86_64__
    return ((W64)lowbits((W64)address, ADDRESS_SPACE_BITS)) >> log2(PAGE_SIZE);
#else
    return ((Waddr)address) >> log2(PAGE_SIZE);
#endif
  }

  Waddr pageid(Waddr address) const { return pageid((void*)address); }

  void make_page_accessible(void* address, spat_t top) {
    setbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void make_page_inaccessible(void* address, spat_t top) {
    clearbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void allow_read(void* address, Waddr size) { make_accessible(address, size, readmap); }
  void disallow_read(void* address, Waddr size) { make_inaccessible(address, size, readmap); }
  void allow_write(void* address, Waddr size) { make_accessible(address, size, writemap); }
  void disallow_write(void* address, Waddr size) { make_inaccessible(address, size, writemap); }
  void allow_exec(void* address, Waddr size) { make_accessible(address, size, execmap); }
  void disallow_exec(void* address, Waddr size) { make_inaccessible(address, size, execmap); }

public:
  //
  // Memory management passthroughs
  //
  void setattr(void* start, Waddr length, int prot);
  int getattr(void* start);

  bool fastcheck(Waddr addr, spat_t top) const {
#ifdef __x86_64__
    // Is it outside of userspace address range?
    // Check disabled to allow access to VDSO in kernel space.
    if unlikely (addr >> 48) return 0;

    W64 chunkid = pageid(addr) >> log2(SPAT_PAGES_PER_CHUNK);

    if unlikely (!top[chunkid])
      return false;

    AddressSpace::SPATChunk& chunk = *top[chunkid];
    Waddr byteid = bits(pageid(addr), 3, log2(SPAT_BYTES_PER_CHUNK));
    return bit(chunk[byteid], lowbits(pageid(addr), 3));
#else // 32-bit
    return bit(top[pageid(addr) >> 3], lowbits(pageid(addr), 3));
#endif
  }

  bool fastcheck(void* addr, spat_t top) const {
    return fastcheck((Waddr)addr, top);
  }

  bool check(void* p, int prot) const {
    if unlikely ((prot & PROT_READ) && (!fastcheck(p, readmap)))
      return false;

    if unlikely ((prot & PROT_WRITE) && (!fastcheck(p, writemap)))
      return false;

    if unlikely ((prot & PROT_EXEC) && (!fastcheck(p, execmap)))
      return false;

    return true;
  }

  bool isdirty(Waddr mfn) { return fastcheck(mfn << 12, dirtymap); }
  void setdirty(Waddr mfn) { make_page_accessible((void*)(mfn << 12), dirtymap); }
  void cleardirty(Waddr mfn) { make_page_inaccessible((void*)(mfn << 12), dirtymap); }

  void resync_with_process_maps();
};

#endif