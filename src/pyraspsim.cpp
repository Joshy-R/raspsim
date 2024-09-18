#include <pybind11/pybind11.h>
#include <raspsim-hwsetup.h>
#include <registers.def>

#include <setjmp.h>
#include <sys/mman.h>
#include <string>
#include <sstream>

namespace py = pybind11;
using namespace py::literals;

#define REG(reg) \
    void set_##reg(W64 value) { setRegisterValue(REG_##reg, value); } \
    W64 get_##reg() { return getRegisterValue(REG_##reg); }


#define XMM(number) \
    void set_xmml##number(W64 value) { setRegisterValue(REG_xmml##number, value); } \
    void set_xmmh##number(W64 value) { setRegisterValue(REG_xmmh##number, value); } \
    W64 get_xmml##number() { return getRegisterValue(REG_xmml##number); } \
    W64 get_xmmh##number() { return getRegisterValue(REG_xmmh##number); }

enum class Prot {
    READ = PROT_READ,
    WRITE = PROT_WRITE,
    EXEC = PROT_EXEC,
    NONE = PROT_NONE,
    RW = PROT_READ | PROT_WRITE,
    RX = PROT_READ | PROT_EXEC,
    RWX = PROT_READ | PROT_WRITE | PROT_EXEC,
};

static void pySetAlignedBuf(void *dst, const void *src, size_t size) {
  if (!dst) {
    throw py::value_error("Destination address is None");
  }

  if (size > Raspsim::getPageSize()) {
    throw py::value_error("Data must be less than or equal to page size");
  }

  if ((((uintptr_t)src) % Raspsim::getPageSize()) + size > Raspsim::getPageSize()) {
    throw py::value_error("Data must not cross page boundaries");
  }

  memcpy(dst, src, size);
}

class AddrRef {
public:
  AddrRef(void* addr): addr(addr) { }
  AddrRef(): addr(0) { }

  operator void*() const { return addr; }
  operator byte*() const { return (W8*)addr; }

  explicit operator W32() const { return *(W32*)addr; }
  explicit operator W64() const { return *(W64*)addr; }
  explicit operator byte() const { return *(byte*)addr; }
  explicit operator float() const { return *(float*)addr; }
  explicit operator double() const { return *(double*)addr; }
  operator py::bytes() {
    return py::bytes((char*)addr, 1);
  }

  AddrRef& operator=(W32 value) { *(W32*)addr = value; return *this; }
  AddrRef& operator=(W64 value) { *(W64*)addr = value; return *this; }
  AddrRef& operator=(byte value) { *(byte*)addr = value; return *this; }
  AddrRef& operator=(float value) { *(float*)addr = value; return *this; }
  AddrRef& operator=(double value) { *(double*)addr = value; return *this; }

  AddrRef operator[](Waddr offset) const { return AddrRef((byte*)addr + offset); }

  void writeOffset(size_t offset, py::bytes&& bts) {
    std::string mem{std::move(bts)};
    pySetAlignedBuf(((char*)addr) + offset, mem.data(), mem.size());
  }

  void write(py::bytes&& bts) {
    std::string mem{std::move(bts)};
    pySetAlignedBuf(addr, mem.data(), mem.size());
  }

  void writeByte(size_t offset, int value) {
    if (value > 0xFF || value < 0) {
      throw py::value_error("Value must be between 0 and 255");
    }

    *(byte*)((char*)addr + offset) = value;
  }

  py::bytes read(Waddr size = 1) {
    return py::bytes((char*)addr, size);
  }


protected:
  void* addr;
};

extern bool ensureMachineInitialized(PTLsimMachine& m, const char* machinename);
extern void simulateInitializedMachine(PTLsimMachine& m);

class RaspsimException : public std::exception {
public:
  RaspsimException(byte exception, W32 errorcode, Waddr virtaddr): exception(exception), errorcode(errorcode), virtaddr(virtaddr) { }

  byte getException() const { return exception; }
  W32 getErrorCode() const { return errorcode; }
  Waddr getVirtAddr() const { return virtaddr; }

  const char* what() const noexcept override {
    return Raspsim::getExceptionName(exception);
  }   


private:
  std::string msg;
  byte exception;
  W32 errorcode;
  Waddr virtaddr;
};

class PyRaspsim : public Raspsim {
public:
  PyRaspsim() : Raspsim() {
    setLogfile("/dev/null");
  }

  REG(rip) REG(rsp)
  REG(rax) REG(rbx) REG(rcx) REG(rdx)
  REG(rsi) REG(rdi) REG(rbp)
  REG(r8) REG(r9) REG(r10) REG(r11) REG(r12) REG(r13) REG(r14) REG(r15)

  XMM(0) XMM(1) XMM(2) XMM(3) XMM(4) XMM(5) XMM(6) XMM(7) XMM(8) XMM(9) XMM(10) XMM(11) XMM(12) XMM(13)


  AddrRef mmap(Waddr start, Prot prot);

  AddrRef getMappedPage(Waddr addr);

  void run();

  static jmp_buf simexit;
  static RaspsimException X86Exception;

};

void Raspsim::handle_syscall_32bit(int semantics) {
  longjmp(PyRaspsim::simexit, 1);
}

void Raspsim::handle_syscall_64bit() {
  longjmp(PyRaspsim::simexit, 1);
}


AddrRef PyRaspsim::mmap(Waddr start, Prot prot) {
  return AddrRef(Raspsim::mmap(start, static_cast<int>(prot)));
}

AddrRef PyRaspsim::getMappedPage(Waddr addr) {
  if (addr % getPageSize() != 0) {
    throw py::value_error("Address must be page-aligned");
  }

  return AddrRef(std::move(Raspsim::getMappedPage(addr)));
}

void PyRaspsim::run() {
  PTLsimMachine* machine = getMachine();

  if (!machine) {
    throw py::value_error(std::string("Cannot find core named '") + getCoreName() + "'");
  }

  if (ensureMachineInitialized(*machine, getCoreName())) {
      throw std::runtime_error(std::string("Cannot initialize core model for '") + getCoreName() + "'");
  }

  if (setjmp(simexit)) {
    throw PyRaspsim::X86Exception;
  } else {
    simulateInitializedMachine(*machine);
  }
}

jmp_buf PyRaspsim::simexit;
RaspsimException PyRaspsim::X86Exception = {0, 0, 0};

#define REG_PROP(r) \
   .def_property(#r, &PyRaspsim::get_##r, &PyRaspsim::set_##r)


PYBIND11_MODULE(raspsim, m) {
    m.doc() = "python binding for raspsim, a cycle-accurate x86 simulator based on PTLsim";
    
    py::class_<AddrRef>(m, "Address")
        .def("__getitem__", &AddrRef::operator[], "offset"_a)
        .def("__setitem__", &AddrRef::writeOffset, "offset"_a, "value"_a)
        .def("__setitem__", &AddrRef::writeByte, "offset"_a, "value"_a)
        .def("read", &AddrRef::read, "size"_a = 1, "Read data from the address")
        .def("write", &AddrRef::write, "value"_a, "Write data to the address");

    py::enum_<Prot>(m, "Prot")
        .value("READ", Prot::READ)
        .value("WRITE", Prot::WRITE)
        .value("EXEC", Prot::EXEC)
        .value("NONE", Prot::NONE)
        .value("RW", Prot::RW)
        .value("RX", Prot::RX)
        .value("RWX", Prot::RWX);

    py::register_exception<RaspsimException>(m, "RaspsimException");

    py::class_<PyRaspsim>(m, "Raspsim")
        .def(py::init<>(), "Initialize the Raspsim object")
        REG_PROP(rip) REG_PROP(rsp)
        REG_PROP(rax) REG_PROP(rbx) REG_PROP(rcx) REG_PROP(rdx)
        REG_PROP(rsi) REG_PROP(rdi)REG_PROP(rbp)
        REG_PROP(r8) REG_PROP(r9) REG_PROP(r10) REG_PROP(r11) REG_PROP(r12) REG_PROP(r13) REG_PROP(r14) REG_PROP(r15)

        .def("run", &PyRaspsim::run, "Run the simulator")
        .def("getMappedPage", &PyRaspsim::getMappedPage, "Get the mapped page")
        .def("disableSSE", &PyRaspsim::disableSSE, "Disable SSE")
        .def("disableX87", &PyRaspsim::disableX87, "Disable X87")
        .def("enablePerfectCache", &PyRaspsim::enablePerfectCache, "Enable perfect cache")
        .def("enableStaticBranchPrediction", &PyRaspsim::enableStaticBranchPrediction, "Enable static branch prediction")
        .def_property_readonly("cycles", &PyRaspsim::cycles, "Get the number of cycles")
        .def_property_readonly("instructions", &PyRaspsim::instructions, "Get the number of instructions")
        .def("mmap", &PyRaspsim::mmap, "Map a page to the virtual address space of the simulator", "start"_a, "prot"_a);        
}



void Raspsim::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  PyRaspsim::X86Exception = {exception, errorcode, virtaddr};
  longjmp(PyRaspsim::simexit, 1);
}
