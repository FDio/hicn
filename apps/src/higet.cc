/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hicn/transport/http/client_connection.h>

#include <fstream>

typedef std::chrono::time_point<std::chrono::system_clock> Time;
typedef std::chrono::milliseconds TimeDuration;

Time t1;

#define DEFAULT_BETA 0.99
#define DEFAULT_GAMMA 0.07

namespace hicnet {

namespace http {

typedef struct {
  std::string file_name;
  bool print_headers;
  std::string producer_certificate;
} Configuration;

void processResponse(Configuration &conf, transport::http::HTTPResponse &&response) {

  auto &payload = response.getPayload();

  if (conf.file_name != "-") {
    std::cerr << "Saving to: " << conf.file_name << " " << payload.size()  << "kB" << std::endl;
  }

  Time t3 = std::chrono::system_clock::now();

  std::streambuf *buf;
  std::ofstream of;

  if (conf.file_name != "-") {
    of.open(conf.file_name, std::ofstream::binary);
    buf = of.rdbuf();
  } else {
    buf = std::cout.rdbuf();
  }

  std::ostream out(buf);

  if (conf.print_headers) {
    auto &headers = response.getHeaders();

    out << "HTTP/" << response.getHttpVersion() << " " << response.getStatusCode() << " " << response.getStatusString()
        << "\n";
    for (auto &h : headers) {
      out << h.first << ": " << h.second << "\n";
    }
    out << "\n";
  }

  out.write((char *) payload.data(), payload.size());
  of.close();

  Time t2 = std::chrono::system_clock::now();;
  TimeDuration dt = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
  TimeDuration dt3 = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t1);
  long msec = dt.count();
  long msec3 = dt3.count();
  std::cerr << "Elapsed Time: " << msec / 1000.0 << " seconds -- " << payload.size() * 8 / msec / 1000.0
            << "[Mbps] -- " << payload.size() * 8 / msec3 / 1000.0 << "[Mbps]" << std::endl;

}

void usage(char *program_name) {
  std::cerr << "USAGE:" << std::endl;
  std::cerr << "\t" << program_name << " [OPTION]... [URL]..." << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << "\t" << "-O filename             write documents to FILE" << std::endl;
  std::cerr << "\t" << "-S                      print server response" << std::endl;
  std::cerr << "EXAMPLE:" << std::endl;
  std::cerr << "\t" << program_name << " -O - http://origin/index.html" << std::endl;
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

  Configuration conf {
      .file_name = "", .print_headers = false, .producer_certificate = ""
  };

  std::string name("http://webserver/sintel/mpd");

  int opt;
  while ((opt = getopt(argc, argv, "O:Sc:")) != -1) {
    switch (opt) {
      case 'O':
        conf.file_name = optarg;
        break;
      case 'S':
        conf.print_headers = true;
        break;
      case 'c':
        conf.producer_certificate = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        break;
    }
  }

  if (argv[optind] == 0) {
    std::cerr << "Using default name " << name << std::endl;
  } else {
    name = argv[optind];
  }

  if (conf.file_name.empty()) {
    conf.file_name = name.substr(1 + name.find_last_of("/"));
  }

  std::map<std::string, std::string> headers = {
      {"Host", "localhost"},
      {"User-Agent", "higet/1.0"}
  };

  transport::http::HTTPClientConnection connection;
  if (!conf.producer_certificate.empty()) {
    connection.setCertificate(conf.producer_certificate);
  }

  t1 = std::chrono::system_clock::now();

  connection.get(name, headers);
  processResponse(conf, connection.response());
  
  return EXIT_SUCCESS;
}

} // end namespace http

} // end namespace hicnet

int main(int argc, char **argv) {
  return hicnet::http::main(argc, argv);
}
