/*
 * rtwradio - bench harness for the experimental radio-ABI bridge in the
 * TahoeRealtekWiFi fork (selectors 6..8 of the RTW control user client).
 *
 * Build: clang -O2 -Wall Tools/rtwradio.c -framework IOKit -framework CoreFoundation -o Tools/rtwradio
 * Use:   sudo Tools/rtwradio status | channels | scan | results | tx <hex>
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <IOKit/IOKitLib.h>
#include <mach/mach_error.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../kext/RTWControl.h"

static io_connect_t open_controller(void) {
    CFDictionaryRef match = IOServiceMatching(RTW_CONTROL_SERVICE_CLASS);
    if (!match) { fprintf(stderr, "IOServiceMatching failed\n"); return 0; }
    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &iter);
    if (kr != KERN_SUCCESS || !iter) {
        fprintf(stderr, "no RTWUSBController service found (kext loaded?)\n");
        return 0;
    }
    io_service_t service = IOIteratorNext(iter);
    IOObjectRelease(iter);
    if (!service) { fprintf(stderr, "service iterator empty\n"); return 0; }
    io_connect_t connect = 0;
    kr = IOServiceOpen(service, mach_task_self(), RTW_CONTROL_USER_CLIENT_TYPE, &connect);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceOpen: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 0;
    }
    return connect;
}

static int call(io_connect_t connect, uint32_t selector, const void *input, size_t inputSize,
                void *output, size_t outputSize) {
    size_t outLen = outputSize;
    kern_return_t kr = IOConnectCallStructMethod(connect, selector, input, inputSize,
                                                 output, &outLen);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "selector %u: 0x%x (%s)\n", selector, kr, mach_error_string(kr));
        return -1;
    }
    return 0;
}

static const char *stateName(uint32_t state) {
    switch (state) {
    case 0: return "IDLE";
    case 1: return "SCAN";
    case 2: return "JOINING";
    case 3: return "LINKED";
    default: return "?";
    }
}

static int cmdStatus(io_connect_t connect) {
    RTWControlRequest request = { RTW_CONTROL_VERSION };
    RTWControlRadioStatus out;
    if (call(connect, RTW_CONTROL_RADIO_STATUS, &request, sizeof(request), &out, sizeof(out)))
        return 1;
    printf("bridge build %u\n", out.build);
    printf("state %s (%u) flags %u%s%s\n", stateName(out.state), out.state, out.flags,
           (out.flags & 1) ? " [data-hook]" : "", (out.flags & 2) ? " [awdl-hook]" : "");
    printf("gates: 5g-band %s board %s features %s single-path %s rf_paths %u\n",
           (out.gates & 1) ? "yes" : "NO",
           (out.gates & 2) ? "known" : "UNKNOWN",
           (out.gates & 4) ? "valid" : "INVALID",
           (out.gates & 8) ? "yes" : "no",
           out.boardRfPaths);
    printf("channel %u band %s bw %u center %u rssi %d dBm\n",
           out.channel, out.band == 1 ? "5G" : "2G", out.bssBw, out.center, out.rssiDbm);
    printf("bssid %02x:%02x:%02x:%02x:%02x:%02x ssid '%.*s'\n",
           out.bssid[0], out.bssid[1], out.bssid[2], out.bssid[3], out.bssid[4], out.bssid[5],
           out.ssidLength, out.ssid);
    if (out.reserved[0] || out.reserved[1])
        printf("last offch failure: errno %lu step %u (1 coex-band 2 tune "
               "3 restore-coex 4 restore-tune 5 range 6 permits)\n",
               (unsigned long)out.reserved[0], out.reserved[1]);
    return 0;
}

static int cmdChannels(io_connect_t connect) {
    RTWControlRequest request = { RTW_CONTROL_VERSION };
    RTWControlRadioChannels out;
    if (call(connect, RTW_CONTROL_RADIO_CHANNELS, &request, sizeof(request), &out, sizeof(out)))
        return 1;
    printf("%u channels:", out.count);
    for (uint32_t i = 0; i < out.count && i < 64; ++i)
        printf(" %u%s", out.channel[i], out.passive[i] ? "*" : "");
    printf("\n(* = passive/DFS)\n");
    return 0;
}

static int cmdScan(io_connect_t connect) {
    RTWControlRequest request = { RTW_CONTROL_VERSION };
    RTWControlReply reply;
    if (call(connect, RTW_CONTROL_SCAN, &request, sizeof(request), &reply, sizeof(reply)))
        return 1;
    printf("scan started\n");
    return 0;
}

static int cmdResults(io_connect_t connect) {
    RTWControlRequest request = { RTW_CONTROL_VERSION };
    RTWControlScanResults out;
    if (call(connect, RTW_CONTROL_SCAN_RESULTS, &request, sizeof(request), &out, sizeof(out)))
        return 1;
    for (uint32_t i = 0; i < out.count; ++i) {
        const RTWControlScanRecord *r = &out.records[i];
        printf("ch%-3u %4d dBm %s '%.*s'\n", r->channel, r->rssi,
               (r->securityFlags & RTW_CONTROL_SECURITY_WPA2_PSK) ? "WPA2" :
               (r->securityFlags & RTW_CONTROL_SECURITY_PRIVACY) ? "encr" : "open ",
               r->ssidLength, r->ssid);
    }
    if (out.truncated) printf("(truncated)\n");
    return 0;
}

static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int cmdTx(io_connect_t connect, const char *hex) {
    RTWControlRadioFrame request;
    memset(&request, 0, sizeof(request));
    request.version = RTW_CONTROL_VERSION;
    size_t hexLength = strlen(hex);
    if (hexLength & 1) { fprintf(stderr, "odd hex length\n"); return 1; }
    if (hexLength / 2 > RTW_CONTROL_RADIO_MAX_FRAME) {
        fprintf(stderr, "frame too long (max %u)\n", RTW_CONTROL_RADIO_MAX_FRAME);
        return 1;
    }
    for (size_t i = 0; i < hexLength; i += 2) {
        int hi = hexValue(hex[i]), lo = hexValue(hex[i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); return 1; }
        request.frame[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    request.length = (uint32_t)(hexLength / 2);
    RTWControlReply reply;
    kern_return_t kr = IOConnectCallStructMethod(connect, RTW_CONTROL_RADIO_TX_80211,
                                                 &request, sizeof(request),
                                                 &reply, &(size_t){ sizeof(reply) });
    if (kr == MACH_SEND_INVALID_DEST || kr == KERN_INVALID_ARGUMENT) {
        fprintf(stderr, "tx rejected at user-client level: 0x%x (%s)\n", kr,
                mach_error_string(kr));
        return 1;
    }
    /* IOReturns surface through the kext; a 0x2bc-style IOReturn passes as kr. */
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "tx: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 1;
    }
    printf("tx accepted (%u bytes)\n", request.length);
    return 0;
}

static int channelArg(const char *text, uint32_t *out) {
    if (!text || !*text) return -1;
    char *end = NULL;
    long value = strtol(text, &end, 0);
    if (!end || *end || value < 0 || value > 255) return -1;
    *out = (uint32_t)value;
    return 0;
}

static int cmdChannelOp(io_connect_t connect, uint32_t selector, const char *text,
                        const char *label) {
    uint32_t value = 0;
    if (channelArg(text, &value)) { fprintf(stderr, "bad %s value\n", label); return 1; }
    RTWControlRadioChannel request = { RTW_CONTROL_VERSION, value, { 0, 0 } };
    RTWControlReply reply;
    if (call(connect, selector, &request, sizeof(request), &reply, sizeof(reply)))
        return 1;
    printf("%s %u accepted\n", label, value);
    return 0;
}

static int cmdTxStat(io_connect_t connect) {
    RTWControlRequest request = { RTW_CONTROL_VERSION };
    RTWControlRadioTxStat out;
    if (call(connect, RTW_CONTROL_RADIO_TXSTAT, &request, sizeof(request), &out, sizeof(out)))
        return 1;
    printf("rate %u (0 = fixed 12 Mb/s) reports %u clean %u lost %u\n",
           out.rate, out.reports, out.clean, out.lost);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "use: rtwradio status|channels|scan|results|tx <hex>|"
                "setchannel <ch>|offch <ch|0>|rate <idx|0>|txstat\n");
        return 2;
    }
    io_connect_t connect = open_controller();
    if (!connect) return 2;
    int result = 1;
    if (!strcmp(argv[1], "status")) result = cmdStatus(connect);
    else if (!strcmp(argv[1], "channels")) result = cmdChannels(connect);
    else if (!strcmp(argv[1], "scan")) result = cmdScan(connect);
    else if (!strcmp(argv[1], "results")) result = cmdResults(connect);
    else if (!strcmp(argv[1], "tx") && argc >= 3) result = cmdTx(connect, argv[2]);
    else if (!strcmp(argv[1], "setchannel") && argc >= 3)
        result = cmdChannelOp(connect, RTW_CONTROL_RADIO_SET_CHANNEL, argv[2], "setchannel");
    else if (!strcmp(argv[1], "offch") && argc >= 3)
        result = cmdChannelOp(connect, RTW_CONTROL_RADIO_OFFCH, argv[2], "offch");
    else if (!strcmp(argv[1], "rate") && argc >= 3)
        result = cmdChannelOp(connect, RTW_CONTROL_RADIO_RATE, argv[2], "rate");
    else if (!strcmp(argv[1], "txstat")) result = cmdTxStat(connect);
    else fprintf(stderr, "unknown command '%s'\n", argv[1]);
    IOServiceClose(connect);
    return result;
}
