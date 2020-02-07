/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

namespace http {

typedef struct {
  std::string file_name;
  bool print_headers;
  std::string producer_certificate;
  std::string ipv6_first_word;
} Configuration;

void processResponse(Configuration &conf,
                     transport::http::HTTPResponse &&response) {
  auto &payload = response.getPayload();

  if (conf.file_name != "-") {
    std::cerr << "Saving to: " << conf.file_name << " " << payload.size()
              << "kB" << std::endl;
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
    out << "HTTP/" << response.getHttpVersion() << " "
        << response.getStatusCode() << " " << response.getStatusString()
        << "\n";
    for (auto &h : headers) {
      out << h.first << ": " << h.second << "\n";
    }
    out << "\n";
  }

  out.write((char *)payload.data(), payload.size());
  of.close();

  Time t2 = std::chrono::system_clock::now();
  TimeDuration dt =
      std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
  TimeDuration dt3 =
      std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t1);
  long msec = (long)dt.count();
  long msec3 = (long)dt3.count();
  std::cerr << "Elapsed Time: " << msec / 1000.0 << " seconds -- "
            << payload.size() * 8 / msec / 1000.0 << "[Mbps] -- "
            << payload.size() * 8 / msec3 / 1000.0 << "[Mbps]" << std::endl;
}

void usage(char *program_name) {
  std::cerr << "usage:" << std::endl;
  std::cerr << program_name << " [option]... [url]..." << std::endl;
  std::cerr << program_name << "options:" << std::endl;
  std::cerr << "-O <output_path>            = write documents to <output_file>"
            << std::endl;
  std::cerr << "-S                          = print server response"
            << std::endl;
  std::cerr << "-P                          = first word of the ipv6 name of "
               "the response"
            << std::endl;
  std::cerr << "example:" << std::endl;
  std::cerr << "\t" << program_name << " -O - http://origin/index.html"
            << std::endl;
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
#ifdef _WIN32
  WSADATA wsaData = {0};
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  Configuration conf;
  conf.file_name = "";
  conf.print_headers = false;
  conf.producer_certificate = "";
  conf.ipv6_first_word = "b001";

  std::string name("http://webserver/sintel/mpd");

  int opt;
  while ((opt = getopt(argc, argv, "O:Sc:P:")) != -1) {
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
      case 'P':
        conf.ipv6_first_word = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        break;
    }
  }

  name = argv[optind];

  std::cerr << "Using name " << name << " and name first word "
            << conf.ipv6_first_word << std::endl;

  if (conf.file_name.empty()) {
    conf.file_name = name.substr(1 + name.find_last_of("/"));
  }

  std::map<std::string, std::string> headers = {{"Host", "localhost"},
                                                {"User-Agent", "higet/1.0"},
                                                {"Connection", "Keep-Alive"}};

  transport::http::HTTPClientConnection connection;
  if (!conf.producer_certificate.empty()) {
    connection.setCertificate(conf.producer_certificate);
  }

  t1 = std::chrono::system_clock::now();

  connection.get("http://httpserver/sintel/3000/seg_init.mp4", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_init.mp4";
  processResponse(conf, connection.response());

  connection.get("http://httpserver/sintel/3000/seg_1.m4s", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_1.m4s";
  processResponse(conf, connection.response());

  connection.get("http://httpserver/sintel/3000/seg_2.m4s", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_2.m4s";
  processResponse(conf, connection.response());

  connection.get("http://httpserver/sintel/3000/seg_3.m4s", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_3.m4s";
  processResponse(conf, connection.response());

  connection.get("http://httpserver/sintel/3000/seg_4.m4s", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_4.m4s";
  processResponse(conf, connection.response());
  connection.get("http://httpserver/sintel/3000/seg_5.m4s", headers, {},
                 nullptr, nullptr, conf.ipv6_first_word);
  conf.file_name = "seg_5.m4s";
  processResponse(conf, connection.response());

#ifdef _WIN32
  WSACleanup();
#endif

  return EXIT_SUCCESS;
}

}  // end namespace http

int main(int argc, char **argv) { return http::main(argc, argv); }
