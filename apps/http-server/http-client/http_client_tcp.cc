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

#include "http_client_tcp.h"
#include "response.h"

#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>

using namespace std;

struct UserData {
  void *out;
  void *curl;
  bool tcp;
  bool first_time;
};

typedef struct UserData UserData;

size_t write_data(void *ptr, size_t size, size_t nmemb, void *user_data) {

  UserData *data = (UserData *)user_data;

  if (data->first_time) {
    double cl;

    int res =
        curl_easy_getinfo(data->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &cl);

    if (res >= 0) {
      *(ostream *)data->out
          << "HTTP/1.0 200 OK\r\nContent-Length: " << std::size_t(cl)
          << "\r\n\r\n";
    }

    data->first_time = false;
  }

  ((icn_httpserver::Response *)data->out)
      ->write((const char *)ptr, size * nmemb);
  //  ((icn_httpserver::Response*) data->out)->send();
  return size * nmemb;
}

HTTPClientTcp::HTTPClientTcp() {
  tcp_ = false;
  first_time = true;
  curl_ = curl_easy_init();
}

void HTTPClientTcp::setTcp() { tcp_ = true; }

HTTPClientTcp::~HTTPClientTcp() { curl_easy_cleanup(curl_); }

bool HTTPClientTcp::download(const std::string &url, std::ostream &out) {
  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

  /* example.com is redirected, so we tell libcurl to follow redirection */
  curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl_, CURLOPT_ACCEPT_ENCODING, "deflate");

  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_data);
  UserData data;
  data.out = &out;
  data.curl = curl_;
  data.tcp = tcp_;
  data.first_time = first_time;

  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &data);

  /* Perform the request, res will get the return code */
  CURLcode res = curl_easy_perform(curl_);

  /* Check for errors */
  if (res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
    return false;
  }

  return true;
}
