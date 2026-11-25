/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RTW_CONTROL_H
#define RTW_CONTROL_H

#include <stddef.h>
#include <stdint.h>

/* Fixed-layout, little-endian v1 ABI shared by the kext and its local client.
 * No pointers, passwords, variable structures, or raw USB/register operations.
 * Every reserved byte, including unused JOIN SSID storage, must be zero.
 * JOIN supports WPA2-Personal with CCMP only. Its PMK is already derived in
 * user space; neither passphrase storage nor key derivation is a kernel API. */
#define RTW_CONTROL_VERSION 1U
#define RTW_CONTROL_USER_CLIENT_TYPE 0U
#define RTW_CONTROL_SERVICE_CLASS "RTWUSBController"
#define RTW_CONTROL_BUNDLE_ID "org.research.TahoeRealtekWiFi"
#define RTW_CONTROL_MAX_SSID 32U
#define RTW_CONTROL_MAX_NETWORKS 64U

enum RTWControlSelector {
    RTW_CONTROL_STATUS = 0,
    RTW_CONTROL_SCAN = 1,
    RTW_CONTROL_JOIN = 2,
    RTW_CONTROL_LEAVE = 3,
    RTW_CONTROL_SCAN_RESULTS = 4,
    RTW_CONTROL_CHANNEL_MAP = 5, /* additive read-only exact registered map */
    /* Experimental radio-ABI bridge (this fork only): a bench harness for the
     * callPlatformFunction surface. Values mirror rtw/RTLRadioABI.h. Old
     * builds reject 5 and everything above; older *drivers* keep working. */
    RTW_CONTROL_RADIO_STATUS = 6,     /* out: RTWControlRadioStatus */
    RTW_CONTROL_RADIO_TX_80211 = 7,   /* in: RTWControlRadioFrame */
    RTW_CONTROL_RADIO_CHANNELS = 8,   /* out: RTWControlRadioChannels */
    RTW_CONTROL_RADIO_SET_CHANNEL = 9, /* in: RTWControlRadioChannel */
    RTW_CONTROL_RADIO_OFFCH = 10,      /* in: RTWControlRadioChannel (0 = BSS) */
    RTW_CONTROL_RADIO_RATE = 11,       /* in: RTWControlRadioChannel (rate index) */
    RTW_CONTROL_RADIO_TXSTAT = 12,     /* out: RTWControlRadioTxStat */
    RTW_CONTROL_SELECTOR_COUNT = 13
};

enum RTWControlStatusFlags {
    RTW_CONTROL_DEVICE = 1U << 0,
    RTW_CONTROL_RADIO = 1U << 1,
    RTW_CONTROL_RUNNING = 1U << 2,
    RTW_CONTROL_AUTHORIZED = 1U << 3,
    RTW_CONTROL_SCANNING = 1U << 4,
    /* Optional output capabilities; ABI v1 layout and reserved bytes unchanged. */
    RTW_CONTROL_SIGNAL_TRACKED = 1U << 5, /* RSSI has driver-enforced freshness. */
    RTW_CONTROL_SIGNAL_HELD = 1U << 6,   /* Valid sample is at least 2 seconds old. */
    /* Independent live station channel groups, not silicon-family claims.
     * Older drivers omit both flags and retain channels 1-11 only. Neither
     * group authorizes DFS, wider channels or the other 5-GHz group. */
    RTW_CONTROL_BAND_5GHZ = 1U << 7, /* low 36/40/44/48 */
    RTW_CONTROL_BAND_5GHZ_HIGH = 1U << 8 /* upper 149/153/157/161/165 */,
    RTW_CONTROL_BAND_2GHZ = 1U << 9,
    RTW_CONTROL_BANDS_EXPLICIT = 1U << 10 /* absence retains legacy 2.4 GHz */,
    /* Managed-station DFS groups. No AP operation or channel144 permission.
     * Advertised only when the registered backend covers the complete group. */
    RTW_CONTROL_BAND_5GHZ_DFS_LOW = 1U << 11, /* 52/56/60/64 */
    RTW_CONTROL_BAND_5GHZ_DFS_MID = 1U << 12, /* 100..140 in steps of4 */
    /* Explicit LEAVE persists until a new user JOIN/SCAN. Automatic app work
     * must respect this per-adapter state; older drivers omit the bit. */
    RTW_CONTROL_USER_RADIO_DISABLED = 1U << 13
};

enum RTWControlSecurityFlags {
    RTW_CONTROL_SECURITY_PRIVACY = 1U << 0,
    RTW_CONTROL_SECURITY_WPA2_PSK = 1U << 1,
    RTW_CONTROL_SECURITY_CCMP = 1U << 2,
    RTW_CONTROL_SECURITY_UNSUPPORTED = 1U << 3
};

typedef struct RTWControlRequest {
    uint32_t version;
    uint32_t reserved[3];
} RTWControlRequest;

typedef struct RTWControlReply {
    uint32_t version;
    uint32_t reserved[3];
} RTWControlReply;

typedef struct RTWControlJoin {
    uint32_t version;
    uint32_t ssidLength;
    uint8_t ssid[RTW_CONTROL_MAX_SSID];
    uint8_t pmk[32];
    uint32_t reserved[2];
} RTWControlJoin;

typedef struct RTWControlStatus {
    uint32_t version;
    uint32_t flags;
    uint32_t state;                 /* net80211 IEEE80211_S_* state value */
    uint32_t channel;               /* IEEE channel number; 0 if unknown */
    int32_t rssi;                   /* dBm; 0 if unavailable */
    uint32_t usbError;              /* most recent IOReturn, or 0 */
    uint8_t mac[6];
    uint8_t bssid[6];
    uint32_t ssidLength;
    uint8_t ssid[RTW_CONTROL_MAX_SSID];
    uint64_t txPackets;
    uint64_t rxPackets;
    uint64_t txErrors;
    uint64_t rxErrors;
    uint32_t reserved[4];
} RTWControlStatus;

typedef struct RTWControlScanRecord {
    uint8_t ssid[RTW_CONTROL_MAX_SSID];
    uint8_t bssid[6];
    uint8_t ssidLength;
    uint8_t channel;
    int16_t rssi;                   /* dBm; 0 if unavailable */
    uint16_t reserved;
    uint32_t securityFlags;
} RTWControlScanRecord;

typedef struct RTWControlScanResults {
    uint32_t version;
    uint32_t count;                 /* number of initialized records, <=64 */
    uint32_t truncated;             /* exactly 0 or 1 */
    uint32_t reserved[3];
    RTWControlScanRecord records[RTW_CONTROL_MAX_NETWORKS];
} RTWControlScanResults;

/* Registered station geometry, not a fresh-BSS/TX lease. Existing v1 layouts
 * and full-group status bits are unchanged. Older drivers reject selector5. */
#define RTW_CONTROL_CHANNEL_MAP_BYTES 32U
typedef struct RTWControlChannelMap {
    uint32_t version;
    uint32_t reserved[3];
    uint8_t channels[RTW_CONTROL_CHANNEL_MAP_BYTES]; /* bitN is IEEE channelN */
} RTWControlChannelMap;

/* ===== Experimental radio-ABI bridge structs (this fork only) ===== */
typedef struct RTWControlRadioStatus {
    uint32_t version;
    uint32_t build;      /* bridge revision of the loaded kext (3 = gates field) */
    uint32_t state;      /* RTL_RADIO_S_* from rtw/RTLRadioABI.h */
    uint32_t flags;      /* bit0 data hook attached, bit1 AWDL hook attached */
    uint32_t channel;    /* 0 if unknown */
    uint32_t band;       /* RTL_RADIO_BAND_* */
    uint32_t bssBw;      /* RTL_RADIO_BW_* */
    uint32_t center;     /* center channel of the operating width */
    int32_t  rssiDbm;    /* dBm; 0 if unavailable */
    uint8_t  bssid[6];
    uint8_t  ssidLength;
    uint8_t  ssid[RTW_CONTROL_MAX_SSID];
    /* bit0 supports88Band(5G), bit1 board known, bit2 features valid,
     * bit3 single active RF path */
    uint32_t gates;
    uint32_t boardRfPaths; /* efuse-reported RF paths */
    uint32_t reserved[2];
} RTWControlRadioStatus;

#define RTW_CONTROL_RADIO_MAX_FRAME 512U
typedef struct RTWControlRadioFrame {
    uint32_t version;
    uint32_t length;     /* 24..512; bytes past length must be zero */
    uint32_t reserved[2];
    uint8_t  frame[RTW_CONTROL_RADIO_MAX_FRAME]; /* 802.11 header+body, no FCS */
} RTWControlRadioFrame;

typedef struct RTWControlRadioChannels {
    uint32_t version;
    uint32_t count;
    uint32_t reserved[2];
    uint8_t  channel[64];
    uint8_t  band[64];      /* RTL_RADIO_BAND_* */
    uint8_t  passive[64];   /* 1 = passive/DFS only */
    uint8_t  reserved2[64];
} RTWControlRadioChannels;

typedef struct RTWControlRadioChannel {
    uint32_t version;
    uint32_t channel;    /* IEEE channel, or 0 for AwdlOffch=BSS, or 0=off for Rate */
    uint32_t reserved[2];
} RTWControlRadioChannel;

typedef struct RTWControlRadioTxStat {
    uint32_t version;
    uint32_t clean;      /* acknowledged at the first try */
    uint32_t retried;    /* 0: the 8821C TX-status report has no retry count */
    uint32_t retried2;   /* 0 */
    uint32_t lost;       /* report says not acked */
    uint32_t rate;       /* the active AWDL rate index, 0 = fixed 12 Mb/s */
    uint32_t reports;    /* TX-status reports seen since load */
    uint32_t reserved;
} RTWControlRadioTxStat;

static inline int rtw_control_channel_map_contains(const RTWControlChannelMap* map,uint32_t channel) {
    return map && channel<256U && (map->channels[channel/8U]&(1U<<(channel%8U)))!=0;
}
static inline int rtw_control_channel_map_valid(const RTWControlChannelMap* map) {
    if(!map||map->version!=RTW_CONTROL_VERSION||map->reserved[0]||map->reserved[1]||map->reserved[2])return 0;
    /* BitN is channelN. Reject every bit outside 1-11, 36-64/4,
     * 100-140/4 and 149-165/4; channel 144 remains excluded. Checking
     * bytes bounds validation to 32 iterations without aligned word loads. */
    static const uint8_t allowed[RTW_CONTROL_CHANNEL_MAP_BYTES]={
        0xfe,0x0f,0x00,0x00,0x10,0x11,0x11,0x11,
        0x01,0x00,0x00,0x00,0x10,0x11,0x11,0x11,
        0x11,0x11,0x20,0x22,0x22,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    for(uint32_t byte=0;byte<RTW_CONTROL_CHANNEL_MAP_BYTES;++byte)
        if(map->channels[byte]&(uint8_t)~allowed[byte])return 0;
    return 1;
}

enum RTWControlValidation {
    RTW_CONTROL_VALID = 0,
    RTW_CONTROL_BAD_SELECTOR,
    RTW_CONTROL_BAD_SIZE,
    RTW_CONTROL_BAD_VERSION,
    RTW_CONTROL_BAD_RESERVED,
    RTW_CONTROL_BAD_SSID
};

static inline size_t rtw_control_input_size(uint32_t selector) {
    if (selector >= RTW_CONTROL_SELECTOR_COUNT) return 0;
    if (selector == RTW_CONTROL_JOIN) return sizeof(RTWControlJoin);
    if (selector == RTW_CONTROL_RADIO_TX_80211) return sizeof(RTWControlRadioFrame);
    if (selector == RTW_CONTROL_RADIO_SET_CHANNEL ||
        selector == RTW_CONTROL_RADIO_OFFCH ||
        selector == RTW_CONTROL_RADIO_RATE) return sizeof(RTWControlRadioChannel);
    return sizeof(RTWControlRequest);
}

/* Keep user-space connection eligibility aligned with this capability's
 * narrow channel contract. Geometry, DFS and other 5-GHz groups do not imply
 * permission to connect; later extensions need an explicit capability. */
static inline int rtw_control_channel_supported(uint32_t channel, uint32_t flags) {
    return (channel >= 1U && channel <= 11U &&
            (!(flags & RTW_CONTROL_BANDS_EXPLICIT) || (flags & RTW_CONTROL_BAND_2GHZ))) ||
        ((flags & RTW_CONTROL_BAND_5GHZ) &&
         (channel == 36U || channel == 40U || channel == 44U || channel == 48U)) ||
        ((flags & RTW_CONTROL_BAND_5GHZ_HIGH) &&
         (channel == 149U || channel == 153U || channel == 157U || channel == 161U || channel == 165U)) ||
        ((flags & RTW_CONTROL_BAND_5GHZ_DFS_LOW) &&
         channel>=52U && channel<=64U && channel%4U==0U) ||
        ((flags & RTW_CONTROL_BAND_5GHZ_DFS_MID) &&
         channel>=100U && channel<=140U && channel%4U==0U);
}

static inline size_t rtw_control_output_size(uint32_t selector) {
    if (selector >= RTW_CONTROL_SELECTOR_COUNT) return 0;
    if (selector == RTW_CONTROL_STATUS) return sizeof(RTWControlStatus);
    if (selector == RTW_CONTROL_SCAN_RESULTS) return sizeof(RTWControlScanResults);
    if (selector == RTW_CONTROL_CHANNEL_MAP) return sizeof(RTWControlChannelMap);
    if (selector == RTW_CONTROL_RADIO_STATUS) return sizeof(RTWControlRadioStatus);
    if (selector == RTW_CONTROL_RADIO_CHANNELS) return sizeof(RTWControlRadioChannels);
    if (selector == RTW_CONTROL_RADIO_TXSTAT) return sizeof(RTWControlRadioTxStat);
    return sizeof(RTWControlReply);
}

/* Read bytes rather than dereferencing possibly unaligned external input. */
static inline uint32_t rtw_control_load32(const uint8_t* bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
        ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static inline int rtw_control_zeroes(const uint8_t* bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) if (bytes[i]) return 0;
    return 1;
}

static inline enum RTWControlValidation rtw_control_validate_request(
    uint32_t selector, const void* input, size_t inputLength) {
    const size_t expected = rtw_control_input_size(selector);
    if (!expected) return RTW_CONTROL_BAD_SELECTOR;
    if (!input || inputLength != expected) return RTW_CONTROL_BAD_SIZE;
    const uint8_t* bytes = (const uint8_t*)input;
    if (rtw_control_load32(bytes) != RTW_CONTROL_VERSION) return RTW_CONTROL_BAD_VERSION;
    if (selector == RTW_CONTROL_JOIN) {
        const uint32_t length = rtw_control_load32(bytes + offsetof(RTWControlJoin, ssidLength));
        if (!length || length > RTW_CONTROL_MAX_SSID) return RTW_CONTROL_BAD_SSID;
        if (!rtw_control_zeroes(bytes + offsetof(RTWControlJoin, ssid) + length,
                               RTW_CONTROL_MAX_SSID - length) ||
            !rtw_control_zeroes(bytes + offsetof(RTWControlJoin, reserved),
                               sizeof(((RTWControlJoin*)0)->reserved)))
            return RTW_CONTROL_BAD_RESERVED;
    } else if (selector == RTW_CONTROL_RADIO_SET_CHANNEL ||
               selector == RTW_CONTROL_RADIO_OFFCH ||
               selector == RTW_CONTROL_RADIO_RATE) {
        if (!rtw_control_zeroes(bytes + offsetof(RTWControlRadioChannel, reserved),
                                sizeof(((RTWControlRadioChannel*)0)->reserved)))
            return RTW_CONTROL_BAD_RESERVED;
    } else if (selector == RTW_CONTROL_RADIO_TX_80211) {
        const uint32_t length = rtw_control_load32(bytes + offsetof(RTWControlRadioFrame, length));
        if (length < 24 || length > RTW_CONTROL_RADIO_MAX_FRAME) return RTW_CONTROL_BAD_SIZE;
        if (!rtw_control_zeroes(bytes + offsetof(RTWControlRadioFrame, reserved),
                               sizeof(((RTWControlRadioFrame*)0)->reserved)) ||
            !rtw_control_zeroes(bytes + offsetof(RTWControlRadioFrame, frame) + length,
                               RTW_CONTROL_RADIO_MAX_FRAME - length))
            return RTW_CONTROL_BAD_RESERVED;
    } else if (!rtw_control_zeroes(bytes + offsetof(RTWControlRequest, reserved),
                                   sizeof(((RTWControlRequest*)0)->reserved))) {
        return RTW_CONTROL_BAD_RESERVED;
    }
    return RTW_CONTROL_VALID;
}

#if defined(__cplusplus)
#define RTW_CONTROL_ASSERT(c, m) static_assert((c), m)
#define RTW_CONTROL_ALIGNOF(t) alignof(t)
#else
#define RTW_CONTROL_ASSERT(c, m) _Static_assert((c), m)
#define RTW_CONTROL_ALIGNOF(t) _Alignof(t)
#endif
RTW_CONTROL_ASSERT(sizeof(RTWControlRequest) == 16, "request ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlRequest) == 4, "request ABI alignment");
RTW_CONTROL_ASSERT(sizeof(RTWControlReply) == 16, "reply ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlReply) == 4, "reply ABI alignment");
RTW_CONTROL_ASSERT(sizeof(RTWControlJoin) == 80, "join ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlJoin) == 4, "join ABI alignment");
RTW_CONTROL_ASSERT(offsetof(RTWControlJoin, pmk) == 40, "PMK ABI offset");
RTW_CONTROL_ASSERT(sizeof(RTWControlStatus) == 120, "status ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlStatus) == 8, "status ABI alignment");
RTW_CONTROL_ASSERT(offsetof(RTWControlStatus, txPackets) == 72, "counter ABI offset");
RTW_CONTROL_ASSERT(sizeof(RTWControlScanRecord) == 48, "scan record ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlScanRecord) == 4, "scan record ABI alignment");
RTW_CONTROL_ASSERT(sizeof(RTWControlScanResults) == 3096, "scan results ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlScanResults) == 4, "scan results ABI alignment");
RTW_CONTROL_ASSERT(offsetof(RTWControlScanResults, records) == 24, "scan records ABI offset");
RTW_CONTROL_ASSERT(sizeof(RTWControlChannelMap) == 48, "channel map ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlChannelMap) == 4, "channel map ABI alignment");
RTW_CONTROL_ASSERT(offsetof(RTWControlChannelMap, channels) == 16, "channel bitmap ABI offset");
RTW_CONTROL_ASSERT(sizeof(RTWControlRadioStatus) == 92, "radio status ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlRadioStatus) == 4, "radio status ABI alignment");
RTW_CONTROL_ASSERT(sizeof(RTWControlRadioFrame) == 528, "radio frame ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlRadioFrame) == 4, "radio frame ABI alignment");
RTW_CONTROL_ASSERT(offsetof(RTWControlRadioFrame, frame) == 16, "radio frame ABI offset");
RTW_CONTROL_ASSERT(sizeof(RTWControlRadioChannels) == 272, "radio channels ABI size");
RTW_CONTROL_ASSERT(RTW_CONTROL_ALIGNOF(RTWControlRadioChannels) == 4, "radio channels ABI alignment");
RTW_CONTROL_ASSERT(sizeof(RTWControlRadioChannel) == 16, "radio channel ABI size");
RTW_CONTROL_ASSERT(sizeof(RTWControlRadioTxStat) == 32, "radio txstat ABI size");
#undef RTW_CONTROL_ASSERT
#undef RTW_CONTROL_ALIGNOF

#endif
