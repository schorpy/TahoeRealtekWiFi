/*
 * Vendor-side glue for the RTL radio ABI data hook (see kext/RTWRadioABI
 * integration in RTWUSBController). The net80211 delivery path consults
 * these before queueing an Ethernet data frame to the interface.
 */
#ifndef _RTW_RADIO_ABI_GLUE_H
#define _RTW_RADIO_ABI_GLUE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Nonzero while an external layer owns the data path. */
int rtw_radio_rx_hook_active(void);

/* Hand one Ethernet-framed mbuf to the hook. Returns 1 if consumed. */
int rtw_radio_rx_hook_deliver(void *mbuf);

#ifdef __cplusplus
}
#endif

#endif /* _RTW_RADIO_ABI_GLUE_H */
