################################################################################
# NCP host component with threading for Bluetooth                              #
################################################################################

# NCP security is disabled per default.
# It can be enabled by assigning a non-zero value to the SECURITY variable
# e.g. via command line like 'make SECURITY=1'.
# If enabled, make sure that openssl is available in your environment.

ifneq (, $(filter $(MAKECMDGOALS), export))
# Collect security resources when exporting.
SECURITY_DEFAULT = 1
else
SECURITY_DEFAULT = 0
endif

SECURITY ?= $(SECURITY_DEFAULT)

override INCLUDEPATHS += \
$(SDK_DIR)/app/bluetooth/common_host/app_sleep \
$(SDK_DIR)/app/bluetooth/common_host/host_comm \
$(SDK_DIR)/app/bluetooth/common_host/host_comm/config \
$(SDK_DIR)/app/bluetooth/common_host/ncp_host \
$(SDK_DIR)/app/bluetooth/common_host/ncp_host/config \
$(SDK_DIR)/app/bluetooth/common_host/system \
$(SDK_DIR)/app/bluetooth/common_host/tcp \
$(SDK_DIR)/app/bluetooth/common_host/uart \
$(SDK_DIR)/platform/common/inc \
$(SDK_DIR)/protocol/bluetooth/inc

ifneq (, $(filter $(OS), posix))
  override INCLUDEPATHS += $(SDK_DIR)/app/bluetooth/common_host/named_socket
endif

override C_SRC += \
$(SDK_DIR)/app/bluetooth/common_host/app_sleep/app_sleep.c \
$(SDK_DIR)/app/bluetooth/common_host/host_comm/host_comm.c \
$(SDK_DIR)/app/bluetooth/common_host/ncp_host/ncp_host.c \
$(foreach OS_i, $(OS), $(SDK_DIR)/app/bluetooth/common_host/tcp/tcp_$(OS_i).c) \
$(foreach OS_i, $(OS), $(SDK_DIR)/app/bluetooth/common_host/uart/uart_$(OS_i).c) \
$(SDK_DIR)/protocol/bluetooth/src/sl_bt_ncp_host.c \
$(SDK_DIR)/protocol/bluetooth/src/sl_bt_ncp_host_api.c

ifneq (, $(filter $(OS), posix))
  override C_SRC += $(SDK_DIR)/app/bluetooth/common_host/named_socket/named_socket.c
endif

override LDFLAGS += -lpthread

# Security related settings
ifneq ($(SECURITY), 0)
  override INCLUDEPATHS += $(SDK_DIR)/app/bluetooth/common_host/ncp_sec
  # openssl is outside of GSDK. Therefore, add it directly as a compiler flag
  # instead of adding it to INCLUDEPATHS.
  ifeq ($(UNAME), darwin)
    override CFLAGS += -I/usr/local/opt/openssl/include
  else
    override CFLAGS += -I/usr/include/openssl
  endif

  override C_SRC += $(SDK_DIR)/app/bluetooth/common_host/ncp_sec/ncp_sec_host.c

  override CFLAGS += -DSECURITY

  override LDFLAGS += -lcrypto
  ifeq ($(UNAME), darwin)
    override LDFLAGS += -L/usr/local/opt/openssl/lib
  endif
endif

ifeq ($(OS), win)
  # Ws2_32: WinSock library
  override LDFLAGS += -lWs2_32
endif
