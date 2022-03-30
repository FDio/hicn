/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <gtest/gtest.h>

extern "C" {
#include <hicn/config/configuration.h>
}

static inline size_t CS_SIZE = 10;
static inline char CONFIG_FILE[] = "setup.conf";
static inline int LOG_LEVEL = LOG_DEBUG;
static inline char LOG_FILE[] = "/dev/null";
static inline uint16_t PORT = 1234;
static inline uint16_t CONF_PORT = 5678;
static inline bool IS_DAEMON_MODE = true;
static inline char PREFIX[] = "b001::/16";
static inline char PREFIX_2[] = "c001::/16";
static inline strategy_type_t STRATEGY_TYPE = STRATEGY_TYPE_BESTPATH;

class ConfigurationTest : public ::testing::Test {
 protected:
  ConfigurationTest() {
    config = configuration_create();
    log_conf.log_level = LOG_FATAL;
    log_conf.log_file = NULL;
  }
  virtual ~ConfigurationTest() { configuration_free(config); }

  configuration_t *config;
};

TEST_F(ConfigurationTest, CreateConfiguration) {
  // Check configuration creation
  ASSERT_NE(config, nullptr);
}

TEST_F(ConfigurationTest, SetGeneralParameters) {
  configuration_set_cs_size(config, CS_SIZE);
  size_t cs_size = configuration_get_cs_size(config);
  EXPECT_EQ(cs_size, CS_SIZE);

  configuration_set_fn_config(config, CONFIG_FILE);
  const char *config_file = configuration_get_fn_config(config);
  EXPECT_EQ(config_file, CONFIG_FILE);

  configuration_set_port(config, PORT);
  uint16_t port = configuration_get_port(config);
  EXPECT_EQ(port, PORT);

  configuration_set_configuration_port(config, CONF_PORT);
  uint16_t conf_port = configuration_get_configuration_port(config);
  EXPECT_EQ(conf_port, CONF_PORT);

  configuration_set_daemon(config, IS_DAEMON_MODE);
  bool is_daemon_mode = configuration_get_daemon(config);
  EXPECT_EQ(is_daemon_mode, IS_DAEMON_MODE);
}

TEST_F(ConfigurationTest, SetLogParameters) {
  configuration_set_loglevel(config, LOG_LEVEL);
  int log_level = configuration_get_loglevel(config);
  EXPECT_EQ(log_level, LOG_LEVEL);
  EXPECT_EQ(log_conf.log_level, LOG_LEVEL);

  configuration_set_logfile(config, LOG_FILE);
  const char *log_file = configuration_get_logfile(config);
  EXPECT_EQ(log_file, LOG_FILE);
  int write_fd = configuration_get_logfile_fd(config);
  EXPECT_NE(write_fd, -1);
}

TEST_F(ConfigurationTest, SetStrategyParameter) {
  configuration_set_strategy(config, PREFIX, STRATEGY_TYPE);
  strategy_type_t strategy_type = configuration_get_strategy(config, PREFIX);
  EXPECT_EQ(strategy_type, STRATEGY_TYPE);

  // Check strategy for non-registered prefix
  strategy_type = configuration_get_strategy(config, PREFIX_2);
  EXPECT_EQ(strategy_type, STRATEGY_TYPE_UNDEFINED);
}
