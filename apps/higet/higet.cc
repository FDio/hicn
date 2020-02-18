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
 * WITHout_ WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hicn/transport/http/client_connection.h>
#include <fstream>
#include <map>

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#include <asio.hpp>
#endif

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

class ReadBytesCallbackImplementation
    : public transport::http::HTTPClientConnection::ReadBytesCallback {
 public:
  ReadBytesCallbackImplementation(std::string file_name, long yet_downloaded)
      : file_name_(file_name),
        temp_file_name_(file_name_ + ".temp"),
        yet_downloaded_(yet_downloaded),
        byte_downloaded_(yet_downloaded),
        work_(std::make_unique<asio::io_service::work>(io_service_)),
        thread_(
            std::make_unique<std::thread>([this]() { io_service_.run(); })) {
    std::streambuf *buf;
    if (file_name_ != "-") {
      of_.open(temp_file_name_, std::ofstream::binary | std::ofstream::app);
      buf = of_.rdbuf();
    } else {
      buf = std::cout.rdbuf();
    }

    out_ = new std::ostream(buf);
  }

  ~ReadBytesCallbackImplementation() {
    if (thread_->joinable()) {
      thread_->join();
    }
  }

  void onBytesReceived(std::unique_ptr<utils::MemBuf> &&buffer) {
    auto buffer_ptr = buffer.release();
    io_service_.post([this, buffer_ptr]() {
      auto buffer = std::unique_ptr<utils::MemBuf>(buffer_ptr);
      if (!first_chunk_read_) {
        transport::http::HTTPResponse http_response(std::move(buffer));
        auto payload = http_response.getPayload();
        auto header = http_response.getHeaders();
        std::map<std::string, std::string>::iterator it =
            header.find("Content-Length");
        if (it != header.end()) {
          content_size_ = yet_downloaded_ + std::stol(it->second);
        }
        out_->write((char *)payload->data(), payload->length());
        first_chunk_read_ = true;
        byte_downloaded_ += payload->length();
      } else {
        out_->write((char *)buffer->data(), buffer->length());
        byte_downloaded_ += buffer->length();
      }

      if (file_name_ != "-") {
        print_bar(byte_downloaded_, content_size_, false);
      }
    });
  }

  void onSuccess(std::size_t bytes) {
    io_service_.post([this, bytes]() {
      if (file_name_ != "-") {
        of_.close();
        delete out_;
        std::size_t found = file_name_.find_last_of(".");
        std::string name = file_name_.substr(0, found);
        std::string extension = file_name_.substr(found + 1);
        if (!exists_file(file_name_)) {
          std::rename(temp_file_name_.c_str(), file_name_.c_str());
        } else {
          int i = 1;
          std::ostringstream sstream;
          sstream << name << "(" << i << ")." << extension;
          std::string final_name = sstream.str();
          while (exists_file(final_name)) {
            i++;
            sstream.str("");
            sstream << name << "(" << i << ")." << extension;
            final_name = sstream.str();
          }
          std::rename(temp_file_name_.c_str(), final_name.c_str());
        }

        print_bar(100, 100, true);
        std::cout << "\nDownloaded " << bytes << " bytes" << std::endl;
      }
      work_.reset();
    });
  }

  void onError(const std::error_code ec) {
    io_service_.post([this]() {
      of_.close();
      delete out_;
      work_.reset();
    });
  }

 private:
  bool exists_file(const std::string &name) {
    std::ifstream f(name.c_str());
    return f.good();
  }

  void print_bar(long value, long max_value, bool last) {
    float progress = (float)value / max_value;
    struct winsize size;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
    int barWidth = size.ws_col - 8;

    std::cout << "[";
    int pos = barWidth * progress;
    for (int i = 0; i < barWidth; ++i) {
      if (i < pos) {
        std::cout << "=";
      } else if (i == pos) {
        std::cout << ">";
      } else {
        std::cout << " ";
      }
    }
    if (last) {
      std::cout << "] " << int(progress * 100.0) << " %" << std::endl
                << std::endl;
    } else {
      std::cout << "] " << int(progress * 100.0) << " %\r";
      std::cout.flush();
    }
  }

 private:
  std::string file_name_;
  std::string temp_file_name_;
  std::ostream *out_;
  std::ofstream of_;
  long yet_downloaded_;
  long content_size_;
  bool first_chunk_read_ = false;
  long byte_downloaded_ = 0;
  asio::io_service io_service_;
  std::unique_ptr<asio::io_service::work> work_;
  std::unique_ptr<std::thread> thread_;
};

long checkFileStatus(std::string file_name) {
  struct stat stat_buf;
  std::string temp_file_name_ = file_name + ".temp";
  int rc = stat(temp_file_name_.c_str(), &stat_buf);
  return rc == 0 ? stat_buf.st_size : -1;
}

void usage(char *program_name) {
  std::cerr << "usage:" << std::endl;
  std::cerr << program_name << " [option]... [url]..." << std::endl;
  std::cerr << program_name << "options:" << std::endl;
  std::cerr
      << "-O <out_put_path>            = write documents to <out_put_file>"
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

  long yetDownloaded = checkFileStatus(conf.file_name);

  std::map<std::string, std::string> headers;
  if (yetDownloaded == -1) {
    headers = {{"Host", "localhost"},
               {"User-Agent", "higet/1.0"},
               {"Connection", "Keep-Alive"}};
  } else {
    std::string range;
    range.append("bytes=");
    range.append(std::to_string(yetDownloaded));
    range.append("-");
    headers = {{"Host", "localhost"},
               {"User-Agent", "higet/1.0"},
               {"Connection", "Keep-Alive"},
               {"Range", range}};
  }
  transport::http::HTTPClientConnection connection;
  if (!conf.producer_certificate.empty()) {
    connection.setCertificate(conf.producer_certificate);
  }

  t1 = std::chrono::system_clock::now();

  http::ReadBytesCallbackImplementation readBytesCallback(conf.file_name,
                                                          yetDownloaded);

  connection.get(name, headers, {}, nullptr, &readBytesCallback,
                 conf.ipv6_first_word);

#ifdef _WIN32
  WSACleanup();
#endif

  return EXIT_SUCCESS;
}

}  // end namespace http

int main(int argc, char **argv) { return http::main(argc, argv); }
