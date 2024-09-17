#ifndef _RASPSIM_HWSETUP_H_
#define _RASPSIM_HWSETUP_H_

#include <typedefs.h>

class AddressSpace;
class Context;

// Class for setting up user space simulation mode and common settup code for the simulator
// Wrapper to static or global state for better binding support
// TODO: (JR) add lock so only a single instance of raspsim can be used at a time
class Raspsim {
public:

  Raspsim();
  ~Raspsim();

  void run();

  int getRegisterIndex(const char* regname);
  void setRegisterValue(int reg, W64 value);
  W64 getRegisterValue(int reg);
  
  byte* getMappedPage(Waddr addr);

  void disableSSE();
  void disableX87();
  void enablePerfectCache();
  void enableStaticBranchPrediction();

  void mmap(Waddr start, Waddr length, int prot);

  W64 cycles();

  Waddr getPageSize() const;

  static void stutdown();
  static AddressSpace& getAddrspace();
  static Context& getContext();


  // Implement as desired depending on the bindings
  static void propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr);

#ifdef __x86_64__
  static void handle_syscall_64bit();
#endif // __x86_64__
  static void handle_syscall_32bit(int semantics);
};

#endif
