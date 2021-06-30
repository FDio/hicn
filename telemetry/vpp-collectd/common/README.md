# Headers for collectd plugins

These headers are required for plugin development but are not shipped with the
`collectd` Ubuntu 20.04 package (as of May 2021):

* [common.h](https://github.com/collectd/collectd/blob/main/src/utils/common/common.h)
* [plugin.h](https://github.com/collectd/collectd/blob/main/src/daemon/plugin.h)
* [meta_data.h](https://github.com/collectd/collectd/blob/main/src/utils/metadata/meta_data.h)

Related issues:
* [GitHub](https://github.com/collectd/collectd/issues/3881)
* [Ubuntu](https://bugs.launchpad.net/ubuntu/+source/collectd/+bug/1929079)
