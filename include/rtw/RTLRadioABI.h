/*
 * RTL radio ABI (ported from DrogaBox/RTL8814Native Source/Driver/RTLRadioABI.h,
 * GPL-2.0 Copyright (c) 2026 DrogaBox). Kept layout-identical so the same
 * IO80211 layer kext can drive either radio through callPlatformFunction.
 */
#ifndef _RTW_RADIO_ABI_H
#define _RTW_RADIO_ABI_H

#include <stdint.h>

#define RTL_RADIO_ABI             2
#define RTL_RADIO_SAE_PASSWORD_MAX 63

/* Function names (OSSymbol keys for callPlatformFunction); p1..p2 below */
#define RTL_RADIO_FN_ABI          "rtlRadioAbi"        /* p1: uint32_t *abi (out) */
#define RTL_RADIO_FN_SCAN_START   "rtlRadioScanStart"  /* p1: const uint32_t *channels or NULL (whole plan), p2: const uint32_t *count */
#define RTL_RADIO_FN_SCAN_COPY    "rtlRadioScanCopy"   /* p1: struct rtl_radio_bss[], p2: uint32_t *count (in: capacity, out: filled) */
#define RTL_RADIO_FN_CHANNELS     "rtlRadioChannels"   /* p1: struct rtl_radio_chan[], p2: uint32_t *count (in/out) */
#define RTL_RADIO_FN_JOIN         "rtlRadioJoin"       /* p1: struct rtl_radio_join * (SAE password consumed and wiped) */
#define RTL_RADIO_FN_STATUS       "rtlRadioStatus"     /* p1: struct rtl_radio_status * (out) */
#define RTL_RADIO_FN_LEAVE        "rtlRadioLeave"      /* no args */
#define RTL_RADIO_FN_MAC          "rtlRadioMac"        /* p1: uint8_t[6] (out) */
#define RTL_RADIO_FN_SET_MAC      "rtlRadioSetMac"     /* p1: const uint8_t[6] */
#define RTL_RADIO_FN_DATA_HOOK    "rtlRadioDataHook"   /* p1: rtl_radio_rx_fn (NULL = detach), p2: void *ctx */
#define RTL_RADIO_FN_TX           "rtlRadioTx"         /* p1: mbuf_t, Ethernet frame (consumed in all cases) */

typedef void (*rtl_radio_rx_fn)(void *ctx, void *mbuf);

/* AWDL (stubs answer kIOReturnUnsupported in this backend) */
#define RTL_RADIO_FN_AWDL_HOOK    "rtlRadioAwdlHook"   /* p1: rtl_radio_awdl_rx_fn (NULL = detach), p2: void *ctx */

typedef void (*rtl_radio_awdl_rx_fn)(void *ctx, const uint8_t *frame, uint32_t len,
                                     int8_t rssi_dbm, uint8_t channel);

#define RTL_RADIO_FN_TX_80211     "rtlRadioTx80211"    /* p1: const uint8_t *frame, p2: uint32_t *len */
#define RTL_RADIO_FN_AWDL_PORT    "rtlRadioAwdlPort"   /* p1: const uint8_t mac[6] or NULL */
#define RTL_RADIO_FN_AWDL_RATE    "rtlRadioAwdlRate"   /* p1: const uint32_t *rate */
#define RTL_RADIO_FN_AWDL_TXSTAT  "rtlRadioAwdlTxStat" /* p1: struct rtl_radio_awdl_txstat * (out) */
struct rtl_radio_awdl_txstat {
	uint32_t clean;
	uint32_t retried;
	uint32_t retried2;
	uint32_t lost;
	uint32_t rate;
	uint32_t reports;
};

#define RTL_RADIO_FN_SET_CHANNEL  "rtlRadioSetChannel" /* p1: const uint32_t *channel */
#define RTL_RADIO_FN_AWDL_OFFCH   "rtlRadioAwdlOffch"  /* p1: const uint32_t *channel (0 = BSS) */
#define RTL_RADIO_FN_AWDL_AGG     "rtlRadioAwdlAgg"    /* p1: struct rtl_radio_awdl_agg * (in, out) */
struct rtl_radio_awdl_agg {
	uint32_t rate;
	uint32_t bw;
	uint32_t sgi;
	uint32_t max_agg;
	uint32_t density;
	uint32_t radio_bw;
};

/* rtl_radio_status.state */
#define RTL_RADIO_S_IDLE          0
#define RTL_RADIO_S_SCAN          1
#define RTL_RADIO_S_JOINING       2
#define RTL_RADIO_S_LINKED        3

#define RTL_RADIO_SCAN_BACKOP     2

#define RTL_RADIO_BAND_2G         0
#define RTL_RADIO_BAND_5G         1

/* Channel widths (bss_bw, rx_bw) */
#define RTL_RADIO_BW_20           0
#define RTL_RADIO_BW_40           1
#define RTL_RADIO_BW_80           2

#define RTL_RADIO_MAX_IES         1024

struct rtl_radio_bss {
	uint8_t  bssid[6];
	uint8_t  ssid_len;
	uint8_t  ssid[32];
	uint8_t  channel;
	uint8_t  band;
	uint8_t  security;         /* 0 = open, 1 = WEP, 2 = WPA, 3 = WPA2 */
	int16_t  rssi_dbm;
	uint16_t capinfo;
	uint16_t intval;
	uint16_t ies_len;
	uint8_t  ies[RTL_RADIO_MAX_IES];
};

struct rtl_radio_chan {
	uint8_t  channel;
	uint8_t  band;
	uint8_t  passive;
	uint8_t  reserved;
};

struct rtl_radio_join {
	uint8_t  ssid_len;
	uint8_t  ssid[32];
	uint8_t  has_pmk;
	uint8_t  pmk[32];
	uint8_t  bssid[6];
	uint8_t  is_sae;
	uint8_t  sae_password_len;
	uint8_t  sae_password[RTL_RADIO_SAE_PASSWORD_MAX];
};

struct rtl_radio_status {
	uint32_t state;
	uint8_t  port_valid;
	uint8_t  rsn;
	uint8_t  bssid[6];
	uint8_t  ssid_len;
	uint8_t  ssid[32];
	uint8_t  channel;
	uint8_t  band;
	uint8_t  bss_bw;
	uint8_t  center;
	int16_t  rssi_dbm;
	uint8_t  tx_rate;
	uint8_t  tx_sgi;
	uint8_t  rx_rate;
	uint8_t  rx_bw;
	uint8_t  rx_sgi;
	uint8_t  nss;
	uint8_t  hook_attached;
	uint8_t  scanning;
	int8_t   noise_dbm;
	uint8_t  idle_channel;
};

#endif /* _RTW_RADIO_ABI_H */
