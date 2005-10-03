//
// PTLsim: Cycle Accurate x86-64 Simulator
// Statistical Analysis Tools
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#include <datastore.h>


const char* labels[] = {
  "L1hit", 
};

#define MAX_BENCHMARKS 256
#define MAX_SHORT_STATS_COUNT 256

stringbuf sbmatrix[MAX_BENCHMARKS][MAX_SHORT_STATS_COUNT];
double totals[MAX_SHORT_STATS_COUNT];

const char* benchnames[MAX_BENCHMARKS];

//
// NOTE: This is for example purposes only; modify as needed:
//
int ooo_get_short_stats(stringbuf* v, double* totals, DataStoreNode& root) {

  int n = 0;

  {
    {
      DataStoreNode& load = root("dcache")("load");
      DataStoreNode& hit = load("hit");

      W64 L1 = hit("L1");
      W64 L2 = hit("L2");
      W64 L3 = hit("L3");
      W64 mem = hit("mem");

      W64 total = (L1 + L2 + L3 + mem);

      double avgcycles = 
        (((double)L1 / (double)total) * 2.0) +
        (((double)L2 / (double)total) * 6.0) +
        (((double)L3 / (double)total) * (5.0 + 20.0)) +
        (((double)mem / (double)total) * (5.0 + 20.0 + 120.0));

      v[n] << floatstring(percent(L1, total), 4, 1);
      totals[n++] += percent(L1, total);

      v[n] << floatstring(percent(L2, total), 4, 1);
      totals[n++] += percent(L2, total);

      v[n] << floatstring(percent(L3, total), 4, 1);
      totals[n++] += percent(L3, total);

      v[n] << floatstring(percent(mem, total), 4, 1);
      totals[n++] += percent(mem, total);

      v[n] << floatstring(avgcycles, 4, 2);
      totals[n++] += avgcycles;
    }
  }

  return n;
}

void collect_short_stats(char** statfiles, int count) {
  assert(count < MAX_BENCHMARKS);

  int n = 0;

  foreach (i, count) {
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    cerr << "Collecting from ", statfiles[i], endl, flush;

    idstream is(statfiles[i]);
    assert(is);

    DataStoreNode& ds = *new DataStoreNode(is);
    n = ooo_get_short_stats(sbmatrix[i], totals, ds("final"));

    const char* p = strchr(statfiles[i], '/');
    benchnames[i] = (p) ? strndup(statfiles[i], p-statfiles[i]) : "Bench";

    delete &ds;
  }

  foreach (i, lengthof(totals)) {
    totals[i] /= (double)count;
  }
}

void print_short_stats_html(ostream& os, int count) {
  os << "<html>", endl;
  os << "<body>", endl;

  os << "<table cols=", count, " rows=", lengthof(labels), " border=1 cellpadding=3 cellspacing=0>";

  os << "<tr><td bgcolor='#c0c0c0'></td>";
  foreach (i, count) {
    os << "<td align=center bgcolor='#c0c0c0'><b>", benchnames[i], "</b></td>";
  }
  os << "</tr>", endl;

  foreach (j, lengthof(labels)) {
    os << "<tr>";
    os << "<td align=right bgcolor='#c0c0c0'><b>", labels[j], "</b></td>", endl;

    foreach (i, count) {
      os << "<td align=right>", sbmatrix[i][j], "</td>";
    }
    os << "</tr>", endl;
  }

  os << "</table>", endl;
  os << "</body>", endl;
  os << "</html>", endl;
}

void print_short_stats_latex(ostream& os, int count) {
  os << "\\documentclass[11pt]{article}", endl;
  os << "\\usepackage[latin1]{inputenc}\\usepackage{color}\\usepackage{graphicx}", endl;
  os << "\\providecommand{\\tabularnewline}{\\\\}", endl;
  os << "\\begin{document}", endl;
  os << "\\begin{tabular}{";
  foreach (i, count+2) { os << "|r"; }
  os << "|}", endl;
  os << "\\hline", endl;

  foreach (i, count) { 
    os << "&\\textsf{\\textbf{\\footnotesize{", benchnames[i], "}}}";
  }

  os << "&\\textsf{\\textbf{\\footnotesize{", "Avg", "}}}";

#if 0
  os << "\\tabularnewline\\hline\\hline", endl;
  os << "\\multicolumn{", count+1, "}{|c|}{\\textsf{\\textbf{\\footnotesize Baseline Processor (AMD Athlon 64 (K8), 2000 MHz)}}}\\tabularnewline\\hline\\hline", endl;

  os << "\\textsf{\\textbf{\\footnotesize{Cycles}}}";
  foreach (i, count) {
    os << "&\\textsf{\\footnotesize{", 0, "}}";
  }

  os << "\\tabularnewline\\hline", endl;

  os << "\\textsf{\\textbf{\\footnotesize{Speedup}}}";
  foreach (i, count) {
    os << "&\\textsf{\\footnotesize{", 0, "}}";
  }

#endif

  os << "\\tabularnewline\\hline\\hline", endl;
  os << "\\multicolumn{", count+2, "}{|c|}{\\textsf{\\textbf{\\footnotesize Experimental Model}}}\\tabularnewline\\hline\\hline", endl;

  foreach (j, lengthof(labels)) {
    os << "\\textsf{\\textbf{\\footnotesize{", labels[j], "}}}";
    foreach (i, count) {
      os << "&\\textsf{\\footnotesize{", sbmatrix[i][j], "}}";
    }
    os << "&\\textsf{\\footnotesize{", floatstring(totals[j], 0, 1), "}}";
    os << "\\tabularnewline\\hline", endl;
  }
  os << "\\end{tabular}", endl;
  os << "\\end{document}", endl;
}

//"fill:#ffffff;fill-opacity:1.0000000;fill-rule:evenodd;stroke:#8080ff;stroke-width:0.10000000;stroke-linecap:butt;stroke-linejoin:miter;stroke-miterlimit:4.0000000;stroke-opacity:1.0000000

struct RGBAColor {
  float r;
  float g;
  float b;
  float a;
};

struct RGBA: public RGBAColor {
  RGBA() { }

  RGBA(float r, float g, float b, float a = 255) {
    this->r = r;
    this->g = g;
    this->b = b;
    this->a = a;
  }

  RGBA(const RGBAColor& rgba) {
    r = rgba.r;
    g = rgba.g;
    b = rgba.b;
    a = rgba.a;
  }
};

ostream& operator <<(ostream& os, const RGBA& rgba) {
  os << '#', hexstring((byte)math::round(rgba.r), 8), hexstring((byte)math::round(rgba.g), 8), hexstring((byte)math::round(rgba.b), 8);
  return os;
}

class SVGCreator {
public:
  ostream* os;
  int idcounter;

  bool filled;
  RGBA fill;
  RGBA stroke;
  float strokewidth;
  char* fontinfo;
  float xoffs;
  float yoffs;

  float dashoffset;
  float dashon;
  float dashoff;

  SVGCreator(ostream& os, float width, float height) {
    this->os = &os;
    idcounter = 0;
    filled = 1;
    fill = RGBA(0, 0, 0, 255);
    stroke = RGBA(0, 0, 0, 255);
    strokewidth = 0.1;
    fontinfo = null;
    setoffset(0, 0);
    setdash(0, 0, 0);
    setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

    printheader(width, height);
  }

  void setdash(float dashoffset, float dashon = 0, float dashoff = 0) {
    this->dashoffset = dashoffset;
    this->dashon = dashon;
    this->dashoff = dashoff;
  }

  void setoffset(float x, float y) {
    xoffs = x; yoffs = y;
  }

  void setfont(const char* font) {
    if (fontinfo) free(fontinfo);
    fontinfo = strdup(font);
  }

  ostream& printstyle(ostream& os) {
    os << "fill:"; if (filled) os << fill; else os << "none"; os << ";";
    os << "fill-opacity:", (fill.a / 255.0), ";";
    if (filled) os << "fill-rule:evenodd;";
    os << "stroke:"; if (strokewidth > 0) os << stroke; else os << "none"; os << ";";
    os << "stroke-width:", strokewidth, ";";
    os << "stroke-linecap:round;stroke-linejoin:miter;stroke-miterlimit:4.0;";
    os << "stroke-opacity:", (stroke.a / 255.0), ";";
    if (dashon) os << "stroke-dashoffset:", dashoffset, ";stroke-dasharray:", dashon, ",", dashoff, endl;
    return os;
  }

  ostream& printfont(ostream& os) {
    os << fontinfo, ';';
    return os;
  }

  void printheader(float width, float height) {
    *os << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", endl;
    *os << "<svg xmlns:svg=\"http://www.w3.org/2000/svg\" xmlns=\"http://www.w3.org/2000/svg\" id=\"svg2\" height=\"", height, "\" width=\"", width, "\" y=\"0.0\" x=\"0.0000000\" version=\"1.0\">", endl;
  }

  void newlayer(const char* name = null) {
    if (!name)
      *os << "<g id=\"", "layer", idcounter++, "\">", endl;
    else *os << "<g id=\"", name, "\">", endl;
  }

  void exitlayer() {
    *os << "</g>", endl;
  }

  void rectangle(float x, float y, float width, float height) {
    *os << "<rect id=\"rect", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" y=\"", (y + yoffs), "\" x=\"", (x + xoffs), "\" height=\"", height, "\" width=\"", width, "\" />", endl;
  }

  void text(const char* string, float x, float y) {
    *os << "<text xml:space=\"preserve\" id=\"text", idcounter++, "\" style=\"";
    printstyle(*os);
    printfont(*os);
    *os << "\" y=\"", y, "\" x=\"", x, "\">", endl;
    *os << "<tspan id=\"tspan", idcounter++, "\" y=\"", (y + yoffs), "\" x=\"", (x + xoffs), "\">", string, "</tspan></text>", endl;
  }

  void line(float x1, float y1, float x2, float y2) {
    *os << "<path id=\"path", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" d=\"M ", (x1 + xoffs), ",", (y1 + yoffs), " L ", (x2 + xoffs), ",", (y2 + yoffs), "\" />", endl;
  }

  void startpath(float x, float y) {
    *os << "<path id=\"path", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" d=\"M ", (x + xoffs), ",", (y + yoffs);
  }

  void nextpoint(float x, float y) {
    *os << " L ", (x + xoffs), ",", (y + yoffs);
  }

  void endpath() {
    *os << "\" />", endl;
  }

  void finalize() {
    *os << "</svg>", endl;
  }

  ~SVGCreator() {
    finalize();
  }
};

static const double logk = 100.;

static inline double logscale(double x) {
  return math::log(1 + (x*logk)) / math::log(1 + logk);
}

static inline double invlogscale(double x) {
  return (math::exp(x*math::log(1 + logk)) - 1) / logk;
}

void create_svg_of_histogram_percent_bargraph(ostream& os, W64s* histogram, int count, double imagewidth = 300.0, double imageheight = 100.0, const RGBA& background = RGBA(225, 207, 255), bool uselogscale = 0) {
  double leftpad = 10.0;
  double toppad = 5.0;
  double rightpad = 4.0;
  double bottompad = 5.0;

  int maxwidth = 0;

  W64 total = 0;
  foreach (i, count) { total += histogram[i]; }

  foreach (i, count) { 
    if (histogram[i] && (((double)histogram[i] / (double)total) >= 0.01)) maxwidth = i;
  }

  double maxheight = 0;
  foreach (i, maxwidth+1) { maxheight = max(maxheight, (double)histogram[i] / (double)total); }

  double xscale = imagewidth / ((double)maxwidth + 1);

  SVGCreator svg(os, imagewidth + leftpad + rightpad, imageheight + toppad + bottompad);
  svg.setoffset(leftpad, toppad);

  svg.newlayer();

  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.0;
  svg.filled = 1;
  svg.fill = background;
  svg.rectangle(0, 0, (maxwidth+1) * xscale, imageheight);

  svg.strokewidth = 0.0;

  svg.fill = RGBA(64, 0, 255);

  foreach (i, maxwidth+1) {
    double x = ((double)histogram[i] / (double)total) / maxheight;
    if (uselogscale) x = logscale(x);
    double barsize = x * imageheight;

    if (barsize >= 0.1) svg.rectangle(i*xscale, imageheight - barsize, xscale, barsize);
  }

  svg.fill = RGBA(0, 0, 0);

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    sb << floatstring(i * maxwidth, 0, 0);
    svg.text(sb, i * imagewidth, imageheight + 3.0);
  }

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:end;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.2) {
    stringbuf sb;
    double value = (uselogscale) ? (invlogscale(i) * maxheight * 100.0) : (i * maxheight * 100.0);
    double y = ((1.0 - i)*imageheight);
    sb << floatstring(value, 0, 0), "%";
    svg.text(sb, -0.2, y - 0.2);

    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(-6, y, (maxwidth+1) * xscale, y);
    svg.strokewidth = 0;
  }

  for (double x = 0; x <= 1.0; x += 0.05) {
    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(x * imagewidth, 0, x * imagewidth, imageheight);
    svg.strokewidth = 0;
  }

  svg.exitlayer();
}

struct TimeLapseFieldsBase {
  W64 start;
  W64 length;
  double values[];
};

//
// NOTE: this is for example purposes only; add additional fields as needed
//
struct TimeLapseFields: public TimeLapseFieldsBase {
  double cache_hit_rate;                          // L1 cache hit rate in percent
};

static const int fieldcount = (sizeof(TimeLapseFields) - sizeof(TimeLapseFieldsBase)) / sizeof(double);

struct LineAttributes {
  bool enabled;
  bool stacked;
  RGBAColor stroke;
  float width;
  float dashoffset;
  float dashon;
  float dashoff;
  bool filled;
  RGBAColor fill;
};

void create_svg_of_percentage_line_graph(ostream& os, double* xpoints, int xcount, double** ypoints, int ycount, 
                                         double imagewidth, double imageheight, const LineAttributes* linetype, const RGBA& background) {
  double leftpad = 10.0;
  double toppad = 5.0;
  double rightpad = 4.0;
  double bottompad = 5.0;

  double xmax = 0;

  foreach (i, xcount) {
    xmax = max(xmax, xpoints[i]);
  }

  double xscale = imagewidth / xmax;

  double yscale = imageheight / 100.0;

  SVGCreator svg(os, imagewidth + leftpad + rightpad, imageheight + toppad + bottompad);
  svg.setoffset(leftpad, toppad);

  svg.newlayer();

  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.1;
  svg.filled = 1;
  svg.fill = background;
  svg.rectangle(0, 0, imagewidth, imageheight);

  svg.strokewidth = 0.1;
  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.1;
  svg.filled = 0;
  svg.fill = RGBA(0, 0, 0);

  double* stackbase = new double[xcount];
  foreach (i, xcount) stackbase[i] = 0;

  foreach (j, ycount) {
    const LineAttributes& line = linetype[j];

    if (!line.enabled)
      continue;
    if (!line.stacked)
      continue;
  
    foreach (i, xcount) {
      ypoints[j][i] += stackbase[i];
      stackbase[i] = ypoints[j][i];
    }
  }

  delete[] stackbase;

  for (int layer = 1; layer >= 0; layer--) {
    for (int j = ycount-1; j >= 0; j--) {
      const LineAttributes& line = linetype[j];
      svg.strokewidth = line.width;
      svg.stroke = line.stroke;
      svg.setdash(line.dashoffset, line.dashon, line.dashoff);
      svg.filled = line.filled;
      svg.fill = line.fill;

      if (!line.enabled)
        continue;

      if (line.stacked != layer)
        continue;

      foreach (i, xcount) {
        double yy = ypoints[j][i];
        double x = xpoints[i] * xscale;
        double y = imageheight - (yy * yscale);
        if (i == 0) x = 0; else if (i == xcount-1) x = imagewidth;
        y = clipto(y, 0, imageheight);
        if (i == 0) { if (line.filled) svg.startpath(0, imageheight); else svg.startpath(x, y); }
        svg.nextpoint(x, y);
      }

      if (line.filled) svg.nextpoint(imagewidth, imageheight);
      svg.endpath();
    }
  }

  svg.filled = 1;
  svg.fill = RGBA(0, 0, 0);
  svg.strokewidth = 0;
  svg.setdash(0);

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    sb << floatstring(i * xmax, 0, 0);
    svg.text(sb, i * imagewidth, imageheight + 4.0);
  }

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:end;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    double value = i * 100.0;

    double y = ((1.0 - i)*imageheight);

    sb << floatstring(value, 0, 0), "%";
    svg.text(sb, -0.3, y - 0.3);

    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(-6, y, imagewidth, y);
    svg.strokewidth = 0;
  }

  for (double x = 0; x <= 1.0; x += 0.05) {
    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(x * imagewidth, 0, x * imagewidth, imageheight);
    svg.strokewidth = 0;
  }

  svg.exitlayer();
}

void create_time_lapse_graph(ostream& os, DataStoreNode& root, const LineAttributes* linetype = null, const RGBA& background = RGBA(225, 207, 255), bool print_table_not_svg = false) {
  dynarray<TimeLapseFields> timelapse;

  int snapshotid = 1;
  for (;;) {
    stringbuf sb;

    sb.reset();
    sb << snapshotid-1;
    DataStoreNode& prev = root(sb);
  
    sb.reset();
    sb << snapshotid;

    DataStoreNode* nodeptr = root.search(sb);
    if (!nodeptr)
      break;

    DataStoreNode& node = root(sb);

    DataStoreNode& diff = *node.subtract(prev);

    TimeLapseFields fields;

    int n = 0;

    fields.start = prev("ptlsim")("cycles");
    fields.length = diff("ptlsim")("cycles");


    {
      DataStoreNode& dcache = diff("dcache");

      {
        DataStoreNode& load = dcache("load");
        DataStoreNode& hit = load("hit");

        W64 L1 = hit("L1");
        W64 L2 = hit("L2");
        W64 L3 = hit("L3");
        W64 mem = hit("mem");
        W64 total = (L1 + L2 + L3 + mem);

        fields.cache_hit_rate = percent(L1, total);
      }
    }

    timelapse.push(fields);

    snapshotid++;

    delete &diff;
  }

  int n = timelapse.length;

  if (print_table_not_svg) {
    os << "Printing ", fieldcount, " fields:", endl;
    foreach (i, n) {
      const TimeLapseFieldsBase& fields = timelapse[i];
      os << "  ", intstring(i, 4), " @ ", intstring((W64)math::round((double)fields.start / 1000000.), 10), "M:";
      
      foreach (j, fieldcount) {
        os << " ", floatstring(fields.values[j], 5, 1);
      }
      os << endl;
    }
    return;
  }

  double* xpoints = new double[timelapse.length];
  double** ypoints = new double*[fieldcount];

  foreach (j, fieldcount) {
    ypoints[j] = new double[timelapse.length];
    foreach (i, timelapse.length) {
      const TimeLapseFieldsBase& snapshot = timelapse[i];
      xpoints[i] = math::round((double)(snapshot.start + snapshot.length) / 1000000.);
      ypoints[j][i] = snapshot.values[j];
    }
  }

  create_svg_of_percentage_line_graph(os, xpoints, timelapse.length, ypoints, fieldcount, 100.0, 50.0, linetype, background);

  foreach (j, fieldcount) {
    delete[] ypoints[j];
  }

  delete[] xpoints;
}

void print_usage() {
  cerr << "Syntax: ptlstats <command> <statsdir> [<statsdir> ...]", endl;
  cerr << "Command is:", endl;
  cerr << "  -dump             Full statistics in text format", endl;
  cerr << "  -dumpraw          Dump raw data store tree nodes", endl;
  cerr << "  -shorthtml        Short statistics of multiple benchmarks in HTML table format", endl;
  cerr << "  -shortlatex       Short statistics of multiple benchmarks in LaTeX table format", endl;
  cerr << "  -graph-all        Graph of numerous statistics plotted over cycles executed", endl;
  cerr << "  -graph-rawdata    Print raw data to be graphed in spreadsheet format", endl;
  cerr << "  -examplehisto     Example histogram", endl;
  cerr << endl;
}

#define NOLINE {0, 0, {0, 0, 0, 0}, 0.00, 0.00, 0.00, 0.00, 0, {0, 0, 0, 0}}

static const LineAttributes linetype_allfields[fieldcount] = {
  {1, 0, {0,   255, 255, 255}, 0.10, 0.00, 0.00, 0.00, 0, {0,   0,   0,   0  }}, // L1 cache hit rate in percent
};


int main(int argc, char* argv[]) {
  argc--;
  if (argc < 2) {
    print_usage();
    return 1;
  }

  char* command = argv[1];

  const char* stats_filename = argv[2];
  idstream is(stats_filename);
  assert(is);

  if (strequal(command, "-dumpraw")) {
    cout << endl, "Loading stats from ", stats_filename, "...", endl, endl;
    DataStoreNode& ds = *new DataStoreNode(is);
    ds.print(cout, true);
    delete &ds;
  } else if (strequal(command, "-shorthtml")) {
    collect_short_stats((char**)(&argv[2]), argc-1);
    print_short_stats_html(cout, argc-1);
  } else if (strequal(command, "-shortlatex")) {
    collect_short_stats((char**)(&argv[2]), argc-1);
    print_short_stats_latex(cout, argc-1);
  } else if (strequal(command, "-graph-rawdata")) {
    DataStoreNode& root = *new DataStoreNode(is);
    create_time_lapse_graph(cout, root, linetype_allfields, RGBA(0, 0, 0), true);
    delete &root;
  } else if (strequal(command, "-graph-all")) {
    DataStoreNode& root = *new DataStoreNode(is);
    create_time_lapse_graph(cout, root, linetype_allfields);
    delete &root;
  } else if (strequal(command, "-examplehisto")) {
    // For example purposes only: modify as needed
    DataStoreNode& root = *new DataStoreNode(is);
    DataStoreNode& ds = root("final")("group")("array-field-name");
    create_svg_of_histogram_percent_bargraph(cout, (W64s*)ds, ds.count, 100.0, 25.0, RGBA(225, 207, 255), 0);
  } else {
    print_usage();
    return 1;
  }
}
