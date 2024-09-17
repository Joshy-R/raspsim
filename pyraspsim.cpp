#include <pybind11/pybind11.h>
#include <raspsim-hwsetup.h>
#include <registers.def>
#include <sys/mman.h>
#include <string>

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

class PyRaspsim : public Raspsim {
public:
  REG(rip) REG(rsp)
  REG(rax) REG(rbx) REG(rcx) REG(rdx)
  REG(rsi) REG(rdi) REG(rbp)
  REG(r8) REG(r9) REG(r10) REG(r11) REG(r12) REG(r13) REG(r14) REG(r15)

  XMM(0) XMM(1) XMM(2) XMM(3) XMM(4) XMM(5) XMM(6) XMM(7) XMM(8) XMM(9) XMM(10) XMM(11) XMM(12) XMM(13)


  void mmap(Waddr start, Waddr length, Prot prot) {
      Raspsim::mmap(start, length, static_cast<int>(prot));
  }

  py::bytes getMappedPage(Waddr addr) {
      byte* page = Raspsim::getMappedPage(addr);
      return py::bytes((char*)page, getPageSize());
  }

  void writePage(Waddr addr, std::string data) {
    if (addr % getPageSize() != 0) {
      throw py::value_error("Address must be page-aligned");
    }

    if (data.size() > getPageSize()) {
      throw py::value_error("Data must be less than or equal to page size");
    }
    
    byte* page = Raspsim::getMappedPage(addr);
    if (!page) {
      throw py::value_error("Page not mapped");
    }

    memcpy(page, data.data(), data.length());
  }

};

#define REG_PROP(r) \
   .def_property(#r, &PyRaspsim::get_##r, &PyRaspsim::set_##r)


PYBIND11_MODULE(raspsim, m) {
    m.doc() = "python binding for raspsim, a cycle-accurate x86 simulator based on PTLsim";

    py::enum_<Prot>(m, "Prot")
        .value("READ", Prot::READ)
        .value("WRITE", Prot::WRITE)
        .value("EXEC", Prot::EXEC)
        .value("NONE", Prot::NONE)
        .value("RW", Prot::RW)
        .value("RX", Prot::RX)
        .value("RWX", Prot::RWX);

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
        .def("cycles", &PyRaspsim::cycles, "Get the number of cycles")
        .def("mmap", &PyRaspsim::mmap, "Map the memory", "start"_a, "length"_a, "prot"_a)
        .def("writePage", &PyRaspsim::writePage, "Write to the page", "addr"_a, "data"_a);

        
}