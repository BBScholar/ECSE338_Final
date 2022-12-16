
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/ioctl.h>

#include "fort.hpp"

namespace fs = std::filesystem;

template <typename T, typename U> using map = std::map<T, U>;
template <typename T> using set = std::set<T>;

using proc_map = std::unordered_map<uint32_t, std::string>;

std::vector<uint32_t> get_pid_list();
void process_pid(uint32_t pid, map<uint32_t, set<std::string>> &proc_map,
                 map<std::string, set<uint32_t>> &obj_map,
                 ::proc_map &proc_names);

void follow_symlink(fs::path &path);

std::string wrap_string(const std::string &s, size_t line_width);

void print_proc(map<uint32_t, set<std::string>> &m, proc_map &proc_names);
void print_obj(map<std::string, set<uint32_t>> &m, proc_map &proc_names);

void print_usage() {
  std::cout << "Usage: shared_info < -obj | -proc >" << std::endl;
  std::cout << "-proc -- sort by process" << std::endl;
  std::cout << "-obj  -- sort by object" << std::endl;
}

int main(int argc, char **argv) {
  argc--;
  argv++;

  if (argc == 0) {
    print_usage();
    return 1;
  }

  bool sort_by_process = true;

  for (int i = 0; i < argc; ++i) {
    std::string arg(argv[i]);
    if (arg == "-proc")
      sort_by_process = true;
    else if (arg == "-obj")
      sort_by_process = false;
    else {
      print_usage();
      return 1;
    }
  }

  map<uint32_t, set<std::string>> proc2obj;
  map<std::string, set<uint32_t>> obj2proc;
  proc_map proc_names;

  const auto pid_list = get_pid_list();

  for (const auto pid : pid_list) {
    process_pid(pid, proc2obj, obj2proc, proc_names);
  }

  // struct winsize w;
  // ioctl(0, TIOCGWINSZ, &w);

  if (sort_by_process) {
    print_proc(proc2obj, proc_names);
  } else {
    print_obj(obj2proc, proc_names);
  }

  return 0;
}

std::vector<uint32_t> get_pid_list() {
  using dir_iter = std::filesystem::directory_iterator;

  std::vector<uint32_t> pids;

  for (const auto &dirEntry : dir_iter("/proc/")) {
    if (!dirEntry.is_directory())
      continue;
    try {
      const uint32_t pid = std::stoul(dirEntry.path().filename().string());
      pids.push_back(pid);
    } catch (std::invalid_argument const &e) {
      continue;
    }
  }

  return pids;
}

void process_pid(uint32_t pid, map<uint32_t, set<std::string>> &proc_map,
                 map<std::string, set<uint32_t>> &obj_map,
                 ::proc_map &proc_names) {
  std::string path("/proc/");
  path.append(std::to_string(pid));
  path.append("/maps");

  std::ifstream in_file(path);
  if (in_file.bad()) {
    std::cerr << "Could not open file: " << path << std::endl;
    return;
  }

  bool found_name = false;

  char so_name[1024];
  for (std::string line; std::getline(in_file, line);) {
    std::sscanf(line.c_str(), "%*llx-%*llx %*s %*llx %*lld:%*lld %*lld %s",
                so_name);

    std::string so_str(so_name);
    so_str.erase(std::remove(so_str.begin(), so_str.end(), '\n'),
                 so_str.cend());
    if (std::strstr(so_name, ".so")) {

      // follow symlinks
      fs::path so_path(so_str);
      follow_symlink(so_path);
      so_str = so_path.string();

      if (!proc_map.contains(pid)) {
        proc_map.insert({pid, set<std::string>()});
      }
      proc_map.at(pid).insert(so_str);

      if (!obj_map.contains(so_str)) {
        obj_map.insert({so_str, set<uint32_t>()});
      }
      obj_map.at(so_name).insert(pid);
    } else if (!found_name && std::strlen(so_name) > 0 &&
               !std::strstr(so_name, "[")) {
      // add process name to list
      proc_names.insert({pid, so_str});
      found_name = true;
    }
  }
  in_file.close();
}

void print_proc(map<uint32_t, set<std::string>> &m, proc_map &proc_names) {
  fort::char_table table;
  table.set_border_style(FT_DOUBLE_STYLE);
  table.row(0).set_cell_content_fg_color(fort::color::blue);
  table.row(0).set_cell_text_style(fort::text_style::bold);

  table << fort::header << "PID"
        << "Process Name"
        << "Shared Objects" << fort::endr;

  for (auto iter = m.begin(); iter != m.end(); iter++) {
    table << std::to_string(iter->first)
          << wrap_string(proc_names[iter->first], 20);
    std::stringstream ss;

    for (auto so_iter = iter->second.begin(); so_iter != iter->second.end();
         so_iter++) {
      if (so_iter != iter->second.begin())
        ss << "\n";
      ss << wrap_string(*so_iter, 128);
      // ss <<  *so_iter;
    }

    table << ss.str() << fort::endr << fort::separator;
  }

  std::cout << table.to_string() << std::endl;
}

void print_obj(map<std::string, set<uint32_t>> &m, proc_map &proc_names) {

  fort::char_table table;
  table.set_border_style(FT_DOUBLE_STYLE);
  table.row(0).set_cell_content_fg_color(fort::color::blue);
  table.row(0).set_cell_text_style(fort::text_style::bold);

  table << fort::header << "Shared Object"
        << "Processes" << fort::endr;

  for (auto iter = m.begin(); iter != m.end(); ++iter) {
    table << wrap_string(iter->first, 56);
    std::stringstream ss;
    for (auto proc_iter = iter->second.begin(); proc_iter != iter->second.end();
         ++proc_iter) {
      if (proc_iter != iter->second.begin())
        ss << "\n";
      ss << wrap_string(proc_names[*proc_iter], 128) << " ("
         << std::to_string(*proc_iter) << ")";
    }
    table << ss.str() << fort::endr << fort::separator;
  }

  std::cout << table.to_string() << std::endl;
}

void follow_symlink(std::filesystem::path &path) {
  while (1) {
    fs::directory_entry dir_ent(path);
    if (!dir_ent.is_symlink()) {
      break;
    }
    path = fs::read_symlink(path);
  }
}

std::string wrap_string(const std::string &s, size_t line_width) {

  if (s.empty())
    return "";

  std::stringstream ss;

  int i = 0;
  int splits = 0;

  for (int i = 0; i < s.size(); ++i) {
    ss << s[i];
    if (i % line_width == 0 && i != 0)
      ss << "\n";
  }

  return ss.str();
}
