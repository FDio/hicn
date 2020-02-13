# Getting started

The Hybrid ICN software distribution can be installed for several platforms.
The network stack comes in two different implementations: one scalable based
on VPP and one portable based on IPC and sockets.

The transport stack is a unique library that is used for both the scalable
and portable network stacks.

## Platforms

- Ubuntu 18.04 LTS (amd64, arm64)
- Debian Stable/Testing
- Red Hat Enterprise Linux 7
- CentOS 7
- Android 10 (amd64, arm64)
- iOS 13
- macOS 10.15
- Windows 10

Other platforms and architectures may work.
You can either use released packages, or compile hicn from sources.

### Ubuntu 18.04/16.04 amd64/arm64

```shell
curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
```

### CentOS 7 amd64

```shell
curl -s https://packagecloud.io/install/repositories/fdio/release/script.rpm.sh | sudo bash
```

### macOS

```shell
brew install hicn
```

### Android

Install the applications via the Google Play Store
<https://play.google.com/store/apps/developer?id=ICN+Team>

### iOS

Coming soon.

### Windows 10

Coming soon.

## License

This software is distributed under the following license:

```shell
Copyright (c) 2017-2020 Cisco and/or its affiliates.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
