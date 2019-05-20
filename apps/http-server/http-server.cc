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

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <iostream>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "http-server/http_server.h"
#include "http_client_icn.h"
#include "http_client_tcp.h"

#ifdef _WIN32
#include <shlobj.h>
#endif

typedef icn_httpserver::HttpServer HttpServer;
typedef icn_httpserver::Response Response;
typedef icn_httpserver::Request Request;

namespace std {

int _isDirectory(const char *path) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) return -1;
  return S_ISDIR(statbuf.st_mode);
}

int _isRegularFile(const char *path) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) return 0;
  return S_ISREG(statbuf.st_mode);
}

string _getFileName(const string &strPath) {
  size_t iLastSeparator = 0;
#ifdef _WIN32
  return strPath.substr(
      (iLastSeparator = strPath.find_last_of("\\")) != std::string::npos
          ? iLastSeparator + 1
          : 0,
      strPath.size() - strPath.find_last_of("."));
#else
  return strPath.substr(
      (iLastSeparator = strPath.find_last_of("/")) != std::string::npos
          ? iLastSeparator + 1
          : 0,
      strPath.size() - strPath.find_last_of("."));
#endif
}

int _mkdir(const char *dir) {
  std::cout << dir << std::endl;
#ifdef _WIN32
  char sepChar = '\\';
  char tmp[MAX_PATH];
#else
  char sepChar = '/';
  char tmp[PATH_MAX];
#endif
  char *p = NULL;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", dir);
  len = strlen(tmp);

  if (tmp[len - 1] == sepChar) tmp[len - 1] = 0;
  for (p = tmp + 1; *p; p++) {
    if (*p == sepChar) {
      *p = 0;
      if (_isDirectory(tmp) != 1) {
#ifdef _WIN32
        if (!CreateDirectory(tmp, NULL)) {
#else
        if (mkdir(tmp, S_IRWXU) == -1) {
#endif
          return -1;
        }
      }
      *p = sepChar;
    }
  }

  if (_isDirectory(tmp) != 1) {
#ifdef _WIN32
    if (!CreateDirectory(tmp, NULL)) {
#else
    if (mkdir(tmp, S_IRWXU) == -1) {
#endif
      return -1;
    }
  }

  return 0;
}

string _getExtension(const string &strPath) {
  size_t iLastSeparator = 0;
  return strPath.substr(
      (iLastSeparator = strPath.find_last_of(".")) != std::string::npos
          ? iLastSeparator + 1
          : 0,
      strPath.size());
}

void default_resource_send(const HttpServer &server,
                           shared_ptr<Response> response,
                           shared_ptr<ifstream> ifs,
                           shared_ptr<vector<char>> buffer,
                           std::size_t bytes_to_read) {
  streamsize read_length;

  if ((read_length = ifs->read(&(*buffer)[0], buffer->size()).gcount()) > 0) {
    response->write(&(*buffer)[0], read_length);

    if (bytes_to_read <= static_cast<std::size_t>(buffer->size())) {
      // If this is the last part of the response, send it at the pointer
      // deletion!
      return;
    }

    std::size_t to_read = bytes_to_read - read_length;
    server.send(response, [&server, response, ifs, buffer,
                           to_read](const std::error_code &ec) {
      if (!ec) {
        default_resource_send(server, response, ifs, buffer, to_read);
      } else {
        cerr << "Connection interrupted" << endl;
      }
    });
  }
}

void afterSignal(HttpServer *webServer, const std::error_code &errorCode) {
  cout << "\nGracefully terminating http-server... wait." << endl;
  webServer->stop();
}

void usage(const char *programName) {
  cerr << "usage: " << programName << " [options]" << endl;
  cerr << programName << " options:" << endl;
  cerr << "-p <root_folder_path>       = path to root folder" << endl;
  cerr << "-f <coniguration_path>      = configuration file path" << endl;
  cerr << "-o <tcp_port>               = tcp listener port" << endl;
  cerr << "-l <webserver_prefix>       = webserver prefix" << endl;
  cerr << "-x <tcp_proxy_prefix>       = tcp proxy prefix" << endl;
  cerr << "-z <hicn_proxy_prefix>      = hicn proxy prefix" << endl;
  cerr << endl;
  cerr << "Web server able to publish content and generate http responses over "
          "TCP/ICN"
       << endl;
  cerr << endl;

  exit(1);
}

int main(int argc, char **argv) {
  // Parse command line arguments

#ifndef _WIN32
  string root_folder = "/var/www/html";
#else
  char path[MAX_PATH];
  SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path);
  string root_folder(path);
  root_folder += "\\www\\html";
#endif
  string webserver_prefix = "http://webserver";
  string tcp_proxy_address;
  string icn_proxy_prefix;
  int port = 8080;
  int opt = 0;

  while ((opt = getopt(argc, argv, "p:l:o:hx:z:")) != -1) {
    switch (opt) {
      case 'p':
        root_folder = optarg;
        break;
      case 'l':
        webserver_prefix = optarg;
        break;
      case 'x':
        tcp_proxy_address = optarg;
        break;
      case 'o':
        port = atoi(optarg);
        break;
      case 'z':
        icn_proxy_prefix = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        break;
    }
  }

  if (_isDirectory(root_folder.c_str()) != 1) {
    if (_mkdir(root_folder.c_str()) == -1) {
      std::cerr << "The web root folder " << root_folder
                << " does not exist and its creation failed. Exiting.."
                << std::endl;
      return (EXIT_FAILURE);
    }
  }

  std::cout << "Using web root folder: [" << root_folder << "]" << std::endl;
  std::cout << "Using locator: [" << webserver_prefix << "]" << std::endl;
  if (!tcp_proxy_address.empty()) {
    std::cout << "Using TCP proxy: [" << tcp_proxy_address << "]" << std::endl;
  }
  if (!icn_proxy_prefix.empty()) {
    std::cout << "Using ICN proxy: [" << icn_proxy_prefix << "]" << std::endl;
  }

  asio::io_service io_service;
  HttpServer server(port, webserver_prefix, 50, 5, 300, io_service);

  // GET for the path /info
  // Responds with some server info
  server.resource["^/info$"]["GET"] = [](shared_ptr<Response> response,
                                         shared_ptr<Request> request) {
    stringstream content_stream;
    content_stream
        << "<h1>This webserver is able to reply to HTTP over TCP/ICN</h1>";
    content_stream << request->getMethod() << " " << request->getPath()
                   << " HTTP/" << request->getHttp_version() << "<br>";

    for (auto &header : request->getHeader()) {
      content_stream << header.first << ": " << header.second << "<br>";
    }

    // find length of content_stream (length received using
    // content_stream.tellp())
    content_stream.seekp(0, ios::end);

    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content_stream.tellp()
              << "\r\n\r\n"
              << content_stream.rdbuf();
  };

  // Default GET-example. If no other matches, this anonymous function will be
  // called. Will respond with content in the web/-directory, and its
  // subdirectories. Default file: index.html Can for instance be used to
  // retrieve an HTML 5 client that uses REST-resources on this server
  server.default_resource["GET"] =
      [&server, &root_folder, &tcp_proxy_address, &icn_proxy_prefix](
          shared_ptr<Response> response, shared_ptr<Request> request) {
        const auto web_root_path = root_folder;
        std::string path = web_root_path;

        // check if there is "/"
        path = path + request->getPath();
        std::cout << "path:" << path << std::endl;
        auto socket_request =
            dynamic_cast<icn_httpserver::SocketRequest *>(request.get());

        std::chrono::milliseconds response_lifetime;
        std::string stem = _getFileName(path);
        std::string extension = _getExtension(path);
        if (extension == "mpd" || stem == "latest") {
          std::cout << "1 second" << std::endl;
          std::cout << "Setting lifetime to 1 second" << std::endl;
          response_lifetime = std::chrono::milliseconds(1000);
        } else {
          std::cout << "5 second" << std::endl;
          std::cout << "Setting lifetime to 5 second" << std::endl;
          response_lifetime = std::chrono::milliseconds(5000);
        }

        response->setResponseLifetime(response_lifetime);

        if (!_isDirectory(path.c_str())) {
          // Check if path is within web_root_path
          if (distance(web_root_path.begin(), web_root_path.end()) <=
                  distance(path.begin(), path.end()) &&
              equal(web_root_path.begin(), web_root_path.end(), path.begin())) {
            if (_isRegularFile(path.c_str())) {
              auto ifs = make_shared<ifstream>();
              ifs->open(path, ifstream::in | ios::binary);

              if (*ifs) {
                // read and send 15 MB at a time
                streamsize buffer_size = 15 * 1024 * 1024;
                auto buffer = make_shared<vector<char>>(buffer_size);

                ifs->seekg(0, ios::end);
                auto length = ifs->tellg();
                ifs->seekg(0, ios::beg);

                response->setResponseLength(length);
                *response << "HTTP/1.0 200 OK\r\nContent-Length: " << length
                          << "\r\n\r\n";

                default_resource_send(server, response, ifs, buffer, length);

                return;
              }
            }
          }
        } else {
          if (distance(web_root_path.begin(), web_root_path.end()) <=
                  distance(path.begin(), path.end()) &&
              equal(web_root_path.begin(), web_root_path.end(), path.begin())) {
            path += "index.html";
            std::cout << "path: "<< path <<endl;
            if (_isRegularFile(path.c_str())) {
              auto ifs = make_shared<ifstream>();
              ifs->open(path, ifstream::in | ios::binary);

              if (*ifs) {
                // read and send 15 MB at a time
                streamsize buffer_size = 15 * 1024 * 1024;
                auto buffer = make_shared<vector<char>>(buffer_size);

                ifs->seekg(0, ios::end);
                auto length = ifs->tellg();
                ifs->seekg(0, ios::beg);

                response->setResponseLength(length);
                *response << "HTTP/1.0 200 OK\r\nContent-Length: " << length
                          << "\r\n\r\n";

                default_resource_send(server, response, ifs, buffer, length);

                return;
              }
            }
          }
        }

        string proxy;
        HTTPClient *client = nullptr;

        if (tcp_proxy_address.empty() && !icn_proxy_prefix.empty()) {
          proxy = icn_proxy_prefix;
          client = new HTTPClientIcn(20);
        } else if (!tcp_proxy_address.empty() && icn_proxy_prefix.empty()) {
          proxy = tcp_proxy_address;
          client = new HTTPClientTcp;
        } else if (!tcp_proxy_address.empty() && !icn_proxy_prefix.empty()) {
          if (socket_request) {
            proxy = icn_proxy_prefix;
            client = new HTTPClientIcn(20);
          } else {
            proxy = tcp_proxy_address;
            client = new HTTPClientTcp;
          }
        }

        if (!proxy.empty()) {
          // Fetch content from remote origin
          std::stringstream ss;

          if (strncmp("http://", proxy.c_str(), 7) != 0) {
            if (strncmp("https://", proxy.c_str(), 8) != 0) {
              ss << "https://";
            } else {
              ss << "http://";
            }
          }

          ss << proxy;
          ss << request->getPath();

          std::cout << "Forwarding request to " << ss.str() << std::endl;

          client->download(ss.str(), *response);

          delete client;

          if (response->size() == 0) {
            *response << "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
          }

          return;
        }

        string content = "Could not open path " + request->getPath() + "\n";

        *response << "HTTP/1.1 404 Not found\r\nContent-Length: "
                  << content.length() << "\r\n\r\n"
                  << content;
      };

  // Let the main thread to catch SIGINT
  asio::signal_set signals(io_service, SIGINT);
  signals.async_wait(bind(afterSignal, &server, placeholders::_1));

  thread server_thread([&server]() {
    // Start server
    server.start();
  });

  if (server_thread.joinable()) {
    server_thread.join();
  }

  return 0;
}

}  // end namespace std

int main(int argc, char **argv) { return std::main(argc, argv); }
