#include "RTWUSBController.hpp"
#include "rtw/NetworkSecurity.h"
#include "RTWUserClient.hpp"
#include "RTWNet80211Globals.hpp"
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IONetworkData.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/usb/IOUSBHostDevice.h>
#include <IOKit/usb/IOUSBHostFamily.h>
#include <IOKit/usb/StandardUSB.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <libkern/OSAtomic.h>
#include <sys/errno.h>
#include <kern/clock.h>
#include <sys/kpi_mbuf.h>
#include <net/kpi_interface.h>
#include <net80211/ieee80211_priv.h>
#include "rtw/RTL8192EU.h"
#include "rtw/USBPackets.h"
#include "RTL8192EUFirmware.inc"
#include "LegacyUSBWiFiFirmware.inc"
#include "RTL8814AUFirmware.inc"
#include "RTL8192DUFirmware.inc"
#include "rtw/DiagnosticPublishPolicy.hpp"
#include <libkern/c++/OSNumber.h>
#include "RTWBandCapabilities.hpp"
#include "RTWPerformanceDiagnostics.inc"
#include "RTWHTDataPath.inc"
#include "RTWFamilyDataPath.inc"

#define super IOEthernetController
OSDefineMetaClassAndStructors(RTWUSBController, IOEthernetController)
static IOReturn fromErrno(int error) {
    switch (error) {
    case 0: return kIOReturnSuccess;
    case EINVAL: return kIOReturnBadArgument;
    case ENOMEM: case ENOBUFS: return kIOReturnNoMemory;
    case EBUSY: case EAGAIN: return kIOReturnBusy;
    case ENODEV: case ENXIO: return kIOReturnNoDevice;
    case ENETDOWN: return kIOReturnNotReady;
    case ETIMEDOUT: return kIOReturnTimeout;
    default: return kIOReturnIOError;
    }
}
RTWUSBController *RTWUSBController::owner(void *p) { return static_cast<RTWUSBController *>(p); }
IOWorkLoop *RTWUSBController::getWorkLoop() const { return loop_ ? loop_ : super::getWorkLoop(); }
IOOutputQueue *RTWUSBController::createOutputQueue() { return IOGatedOutputQueue::withTarget(this, loop_, 256); }
UInt32 RTWUSBController::getFeatures() const { return 0; }
IOReturn RTWUSBController::getPacketFilters(const OSSymbol *group,UInt32 *filters) const {
    if(!filters)return kIOReturnBadArgument;
    *filters=0;
    if(group!=gIONetworkFilterGroup)return kIOReturnUnsupported;
    *filters=kIOPacketFilterUnicast|kIOPacketFilterBroadcast|kIOPacketFilterMulticast;
    return kIOReturnSuccess;
}
IOReturn RTWUSBController::setMulticastMode(bool) {
    /* The pinned MAC profile receives multicast with MAR all ones. The stack
     * applies station/BSSID, RSN, MIC and controlled-port checks. */
    return kIOReturnSuccess;
}
IOReturn RTWUSBController::setMulticastList(IOEthernetAddress *addresses,UInt32 count) {
    return !addresses&&count ? kIOReturnBadArgument : kIOReturnSuccess;
}
IOReturn RTWUSBController::selectMedium(const IONetworkMedium *medium) {
    return medium && setSelectedMedium(medium) ? kIOReturnSuccess : kIOReturnBadArgument;
}
bool RTWUSBController::authorized() const {
    return attached_ && running_ && radioReady_ && joinRequested_ && present_ &&
        !sleeping_ && !dfsTXBlocked() && usbError_ == kIOReturnSuccess && !core_.core_error &&
        core_.sc_ic.ic_state == IEEE80211_S_RUN && core_.sc_ic.ic_bss &&
        (family_!=RTW_WIFI_RTL8814AU||(!acCore_.io_error&&acCore_.phy_initialized&&uses8814FirmwareRate()))&&
        (!is8812Family()||uses8812FirmwareRate())&&(!is88Family()||uses88FirmwareRate())&&(family_!=RTW_WIFI_RTL8192DU||uses8192DUFirmwareRate())&&(!is8192FUFamily()||uses8192FUFirmwareRate())&&(!is8710BUFamily()||uses8710BUFirmwareRate())&&(!is8723Family()||uses8723FirmwareRate())&&core_.sc_ic.ic_bss->ni_port_valid;
}
bool RTWUSBController::setLinkStatus(UInt32 state, const IONetworkMedium *medium, UInt64 speed, OSData *data) {
    if ((state & kIONetworkLinkActive) && !authorized()) {
        state = kIONetworkLinkValid; medium = nullptr; speed = 0;
    }
    bool result=super::setLinkStatus(state, medium, speed, data);
    if((state&kIONetworkLinkActive)&&authorized()){
        cancelWpaRecovery();wpaRecovery_.state=WPARecoveryAuthorized;
        if(auto*queue=getOutputQueue())queue->start();
    }
    return result;
}
bool RTWUSBController::configureInterface(IONetworkInterface *interface) {
    if (!super::configureInterface(interface)) return false;
    IONetworkData *data = interface->getParameter(kIONetworkStatsKey);
    IOEthernetInterface *ethernet = OSDynamicCast(IOEthernetInterface, interface);
    if (!data || !ethernet || !(stats_ = const_cast<IONetworkStats *>(static_cast<const IONetworkStats *>(data->getBuffer())))) return false;
    // Interface presentation only; retain the USB provider and BSD identity.
    ethernet->setProperty(kIOBuiltin, true);
    core_.sc_ic.ic_if.netStat = stats_;
    ether_ifattach(&core_.sc_ic.ic_if, ethernet);
    return true;
}
IOReturn RTWUSBController::getHardwareAddress(IOEthernetAddress *address) {
    if (!address) return kIOReturnBadArgument;
    if (!macReady_) return kIOReturnNotReady;
    /* rtlair>=2: the dummy MAC MUST STAY on this raw ifnet. Without it the
     * InterfaceNamer collision (this ifnet and the layer's interface both
     * carry the radio MAC at birth — the layer's randomized MAC is only
     * applied at join time) leaves the layer's interface UNNAMED -> the
     * port falls back to Ethernet -> airportd never adopts -> no toggle
     * (boot 16 proved the revert regresses this).
     * COST (accepted): the APP's path rides this ifnet; the hotspot's lease
     * filter drops the never-leased dummy MAC -> the app connects but gets
     * 169.254. The NATIVE path is unaffected: its DHCP identity = the
     * layer's interface MAC, which rtlRadioSetMac applies to the radio
     * itself — consistent over the air. */
    uint32_t rtlair = 0;
    if (PE_parse_boot_argn("rtlair", &rtlair, sizeof(rtlair)) && rtlair >= 2) {
        static const uint8_t dummy[6] = {0x02, 0x00, 0x54, 0x52, 0x57, 0x00};
        memcpy(address->bytes, dummy, sizeof(dummy));
        return kIOReturnSuccess;
    }
    *address = mac_; return kIOReturnSuccess;
}
void RTWUSBController::fault(IOReturn error) {
    if (error == kIOReturnSuccess) return;
    if (usbError_ == kIOReturnSuccess) usbError_ = error;
    clear88Discovery(true);
    resetDFSStation();
    radioReady_ = false;
    if (attached_) core_.sc_ic.ic_if.if_link_state = LINK_STATE_DOWN;
    super::setLinkStatus(kIONetworkLinkValid);
}
int RTWUSBController::vendorRequest(bool input, uint16_t address, uint8_t *bytes, size_t length) {
    if (!present_ || !usbOpened_ || !usb_ || sleeping_ || usbError_ != kIOReturnSuccess) return ENXIO;
    if (!bytes || !length || length > 254) return EINVAL;
    if(!input)rtw_dfs_txpause_guard(dfsTXHold_,family_==RTW_WIFI_RTL8192DU,address,bytes,length);
    StandardUSB::DeviceRequest request{};
    request.bmRequestType = input ? 0xc0 : 0x40;
    request.bRequest = 0x05; request.wValue = OSSwapHostToLittleInt16(address);
    request.wIndex = 0; request.wLength = OSSwapHostToLittleInt16((uint16_t)length);
    uint32_t actual = 0;
    IOReturn result = usb_->deviceRequest(request, bytes, actual, 1000);
    if (result != kIOReturnSuccess || actual != length) {
        fault(result == kIOReturnSuccess ? kIOReturnUnderrun : result); return EIO;
    }
    return 0;
}
uint32_t RTWUSBController::readRegister(uint16_t address, uint8_t width) {
    uint8_t bytes[4]{};
    if ((width != 1 && width != 2 && width != 4) || vendorRequest(true,address,bytes,width)) return 0xffffffffU;
    uint32_t value = bytes[0];
    if (width >= 2) value |= (uint32_t)bytes[1] << 8;
    if (width == 4) value |= (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
    return value;
}
int RTWUSBController::writeRegister(uint16_t address, uint8_t width, uint32_t value) {
    uint8_t bytes[4] = {(uint8_t)value,(uint8_t)(value>>8),(uint8_t)(value>>16),(uint8_t)(value>>24)};
    if (width != 1 && width != 2 && width != 4) return EINVAL;
    return vendorRequest(false,address,bytes,width);
}
uint8_t RTWUSBController::read1(void *p,uint16_t a) {
    auto*s=owner(p);
    const bool h2cPoll=s->calibDiag_.active&&a==R92C_HMETFR;
    const uint64_t started=h2cPoll?nowMS():0;
    uint8_t value=(uint8_t)s->readRegister(a,1);
    if(h2cPoll){
        s->calibDiag_.lastH2CPolls++;
        s->calibDiag_.totalH2CPolls++;
        s->calibDiag_.lastH2CReadMS+=nowMS()-started;
    }
    return value;
}
uint16_t RTWUSBController::read2(void *p,uint16_t a) { return (uint16_t)owner(p)->readRegister(a,2); }
uint32_t RTWUSBController::read4(void *p,uint16_t a) { return owner(p)->readRegister(a,4); }
void RTWUSBController::write1(void*p,uint16_t a,uint8_t v) { (void)owner(p)->writeRegister(a,1,v); }
void RTWUSBController::write2(void*p,uint16_t a,uint16_t v) { (void)owner(p)->writeRegister(a,2,v); }
void RTWUSBController::write4(void*p,uint16_t a,uint32_t v) { (void)owner(p)->writeRegister(a,4,v); }
void RTWUSBController::delayUS(void*,uint32_t us) { if (us >= 1000) IOSleep((us+999)/1000); else IODelay(us); }
int RTWUSBController::writeRegion(void*p,uint16_t a,const uint8_t*b,size_t n) {
    if (!b || !n || n > 254) return EINVAL;
    uint8_t copy[254]; memcpy(copy,b,n); return owner(p)->vendorRequest(false,a,copy,n);
}
int RTWUSBController::ioError(void*p) {
    auto *s=owner(p); return !s->present_ || s->sleeping_ || s->usbError_ != kIOReturnSuccess ? EIO : 0;
}
int RTWUSBController::busPower(void*p) { return rtw92eu_power_on(&owner(p)->core_); }
int RTWUSBController::busDMA(void*p) { auto*s=owner(p); return rtw92eu_dma_init(&s->core_,s->endpoints_.num_bulk_out); }
int RTWUSBController::busFirmware(void*p,int page,uint8_t*b,int n) { return rtw92eu_fw_loadpage(&owner(p)->core_,page,b,n); }
int RTWUSBController::loadFirmware(void*p,u_char **bytes,size_t *length) {
    if (!bytes || !length) return EINVAL;
    *bytes=nullptr;*length=0;
    auto*s=owner(p);const uint8_t*image=nullptr;size_t count=0;
    switch(s->family_){
    case RTW_WIFI_RTL8192EU:image=RTW8192EUFirmware;count=sizeof(RTW8192EUFirmware);break;
    case RTW_WIFI_RTL8188EU:image=rtl8188eu;count=sizeof(rtl8188eu);break;
    case RTW_WIFI_RTL8192CU:
        if((s->core_.chip&(RTWN_CHIP_UMC_A_CUT|RTWN_CHIP_92C))==RTWN_CHIP_UMC_A_CUT){image=rtl8192cU;count=sizeof(rtl8192cU);}
        else {image=rtl8192cT;count=sizeof(rtl8192cT);}
        break;
    default:return ENODEV;
    }
    rtw_8192eu_fw_info info{};
    if(!rtw_usb_wifi_inspect_firmware(s->family_,image,count,&info))return EINVAL;
    *bytes=static_cast<u_char *>(::malloc(count,0,0));
    if (!*bytes) return ENOMEM;
    memcpy(*bytes,image,count);*length=count;return 0;
}
void RTWUSBController::busMAC(void*p) { auto*s=owner(p);int e=rtw92eu_mac_init(&s->core_);if(e&&!s->core_.core_error)s->core_.core_error=e; }
void RTWUSBController::busBB(void*p) { auto*s=owner(p);int e=rtw92eu_bb_init(&s->core_);if(e&&!s->core_.core_error)s->core_.core_error=e; }
void RTWUSBController::busAggregation(void*p) { auto*s=owner(p);int e=rtw92eu_aggr_init(&s->core_,s->rxPipe_->getSpeed()==kUSBHostConnectionSpeedHigh);if(e&&!s->core_.core_error)s->core_.core_error=e; }
int RTWUSBController::busAllocate(void*p) { auto*s=owner(p);if(s->isLegacyRecoveryFamily()){const int e=s->beginFamilyStart();if(e)return e;}return s->allocateTransfers(); }
int RTWUSBController::busInitialize(void*p) {
    auto*s=owner(p);
    const auto* initialBackend=rtw_backend_for_family(s->family_);
    const bool initialStation=initialBackend&&(initialBackend->capabilities&RTW_BACKEND_CAP_KEXT_STATION);
    auto cancelled=[&]{return !s->attached_||!s->present_||s->sleeping_||s->stopping_||s->closing_;};
    if(initialStation&&cancelled())return ENXIO;
    if (!s->core_.sc_ic.ic_if.iface || !s->stats_ || ioError(p)) return ENXIO;
    if(initialStation&&(s->rxRecovery_.initialDrainMask||s->rxRecovery_.stopDrainMask))return EBUSY;
    if(s->family_==RTW_WIFI_RTL8192EU){write1(p,R92C_ACLK_MON,0);write1(p,R92C_USB_HRPWM,0);}
    if (ioError(p)) return EIO;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(s->completionLock_);
    bool restart=rtw_transfer_restart(&s->ledger_);IOSimpleLockUnlockEnableInterrupt(s->completionLock_,lock);
    if(!restart)return EBUSY;
    s->running_=true;
    int error=0;unsigned attempted=0;
    for(unsigned i=0;i<RXSlots;i++){
        attempted=i+1;error=s->submit(i,s->rxPipe_,rtw_usb_rx_capacity(s->family_));if(error)break;
    }
    if(initialStation&&cancelled()){s->abortTransfers();return ENXIO;}
    if(initialStation&&(!error||error==EAGAIN)){
        /* A callback can precede the return of the final successful io().
         * Accepted reads with an already-recorded error are not a valid RX
         * epoch, even though their ownership bits are still pending. */
        IOReturn completedError=kIOReturnSuccess;
        lock=IOSimpleLockLockDisableInterrupt(s->completionLock_);
        const bool fullSet=(s->ledger_.pending&((1U<<RXSlots)-1U))==((1U<<RXSlots)-1U);
        for(unsigned i=0;i<RXSlots;i++)if(s->ledger_.completed&(1U<<i)){
            const auto&t=s->transfers_[i];
            if(t.result!=kIOReturnSuccess||t.actual>t.submitted){
                completedError=t.result==kIOReturnSuccess?kIOReturnUnderrun:t.result;
                error=completedError==kIOReturnNotResponding&&!t.actual?EAGAIN:EIO;
                if(error!=EAGAIN)break;
            }
        }
        IOSimpleLockUnlockEnableInterrupt(s->completionLock_,lock);
        if(error&&error!=EAGAIN)s->fault(completedError);
        if(!error&&!fullSet){s->abortTransfers();return EBUSY;}
    }
    if(error){
        if(!initialStation||error!=EAGAIN){s->abortTransfers();return EIO;}
        auto&r=s->rxRecovery_;
        ++r.initialErrors;r.initialOriginalError=kIOReturnNotResponding;
        r.initialDrainMask=(1U<<attempted)-1U;
        for(unsigned i=0;i<attempted;i++)r.initialDrainGeneration[i]=s->transfers_[i].generation;
        /* Never wait for workloop callbacks here. Synchronous abort records
         * what it can, then the ledger proves whether old ownership drained. */
        s->abortTransfers();
        lock=IOSimpleLockLockDisableInterrupt(s->completionLock_);
        const bool drained=rtw_transfer_drained(&s->ledger_);
        IOSimpleLockUnlockEnableInterrupt(s->completionLock_,lock);
        if(r.initialDrainError!=kIOReturnSuccess)return EIO;
        if(!drained||r.initialDrainMask)return EBUSY;
        if(cancelled())return ENXIO;
        if(r.initialConsecutive>=3){
            ++r.initialFailures;++r.initialExhausted;s->fault(r.initialOriginalError);return EIO;
        }
        ++r.initialConsecutive;++r.initialClearAttempts;
        /* advanceRXRecovery uses this same gate-held clear operation. There
         * is one checked call, no sleep/poll/refill loop and no radio success.
         * The next explicit start reboots hardware and submits a fresh set. */
        r.initialClearResult=s->rxPipe_->clearStall(true);
        if(r.initialClearResult!=kIOReturnSuccess){
            ++r.initialFailures;s->fault(r.initialClearResult);return EIO;
        }
        return cancelled()?ENXIO:EAGAIN;
    }
    /* rtwn_init already rebuilt DMA and reloaded firmware. Successful RX
     * submission certifies a fresh transport for untagged CCX feedback. */
    if(s->family_==RTW_WIFI_RTL8188EU){
        write1(p,R88E_TX_RPT_CTRL,read1(p,R88E_TX_RPT_CTRL)|R88E_TX_RPT_CTRL_EN);
        if(ioError(p)){s->abortTransfers();return EIO;}
    }
    if(initialStation)s->rxRecovery_.initialConsecutive=0;
    s->rateTransportFresh_=true;
    s->watchdogTimer_->setTimeoutMS(1000);return 0;
}
void RTWUSBController::busStop(void*p) {
    auto*s=owner(p);s->familyRecovery_.inStop=true;
    if(s->familyRecovery_.starting&&s->core_.core_error)s->failFamilyStart(s->core_.core_error);
    s->abortTransfers();
    if(!s->familyStopDrained())return;
    int cleanup=ENXIO;
    if(s->isLegacyRecoveryFamily()&&s->present_&&!s->sleeping_&&s->usbError_==kIOReturnSuccess)
        cleanup=rtwLegacyPowerOffChecked(&s->core_);
    s->recordFamilyCleanup(cleanup);s->freeTransfers();
}
int RTWUSBController::busBusy(void*p) { return owner(p)->hasFreeTX()?0:1; }
void RTWUSBController::nextScan(void*p) { auto*s=owner(p);if(s->running_&&!s->stopping_)s->scanTimer_->setTimeoutMS(200); }
void RTWUSBController::cancelScan(void*p) { auto*s=owner(p);if(s->scanTimer_)s->scanTimer_->cancelTimeout(); }
void RTWUSBController::nextCalibration(void*p) { auto*s=owner(p);if(s->running_&&!s->stopping_)s->calibTimer_->setTimeoutMS(2000); }
void RTWUSBController::cancelCalibration(void*p) { auto*s=owner(p);if(s->calibTimer_)s->calibTimer_->cancelTimeout(); }
void RTWUSBController::waitAsync(void*) { /* All rtwn work executes on this same serialized workloop. */ }
int RTWUSBController::transmit(void*p,mbuf_t m,ieee80211_node*n) { return owner(p)->sendFrame(m,n); }
int RTWUSBController::stateTransition(ieee80211com *ic,ieee80211_state state,int argument) {
    auto*core=static_cast<rtwn_softc *>(ic->ic_softc);
    auto*s=owner(core->sc_ops.cookie);
    if(s->wpaRecovery_.state==WPARecoveryFailed&&
       (state==IEEE80211_S_AUTH||state==IEEE80211_S_ASSOC||state==IEEE80211_S_RUN))return ETIMEDOUT;
    if (!s->joinRequested_ && (state==IEEE80211_S_AUTH || state==IEEE80211_S_ASSOC || state==IEEE80211_S_RUN))
    {
        ieee80211_begin_scan(&ic->ic_if);
        return rtwn_io_error(core);
    }
    if(state!=ic->ic_state||ic->ic_state==IEEE80211_S_RUN)s->resetRateControl();
    const auto previous=ic->ic_state;
    unsigned requestedChannel=0;
    if(ic->ic_bss&&ic->ic_bss->ni_chan&&ic->ic_bss->ni_chan!=IEEE80211_CHAN_ANYC)
        requestedChannel=ieee80211_chan2ieee(ic,ic->ic_bss->ni_chan);
    if(!s->dfsStateAllowed(state,requestedChannel)){if(state==IEEE80211_S_AUTH&&!s->dfsTXBlocked())s->stopDFSStation();return EACCES;}
    if(state==IEEE80211_S_AUTH){const int power=s->prepareDFSPower(requestedChannel);if(power){s->stopDFSStation();return power;}}
    rtw_signal_reset(&s->signal_);
    int result=s->is8723Family()?s->state8723(ic,state,argument):s->is8710BUFamily()?s->state8710BU(ic,state,argument):s->is8192FUFamily()?s->state8192FU(ic,state,argument):s->family_==RTW_WIFI_RTL8192DU?s->state8192DU(ic,state,argument):s->is88Family()?s->state88(ic,state,argument):s->is8812Family()?s->state8812(ic,state,argument):s->family_==RTW_WIFI_RTL8814AU?s->state8814(ic,state,argument):rtwn_newstate(ic,state,argument);
    /* Some legacy register callbacks report a latched I/O error separately
     * from the backend return. It must not become a successful visit claim;
     * the diagnostic check leaves the transition's return value unchanged. */
    s->dfsStateChanged(state,requestedChannel,result?result:rtwn_io_error(core));
    s->observeScanTransition(previous,state,requestedChannel,result?result:rtwn_io_error(core));
    if(!result&&state==IEEE80211_S_RUN){s->lastBeaconMs_=nowMS();s->resetRateControl();}
    else if(state==IEEE80211_S_SCAN||state==IEEE80211_S_INIT)s->lastBeaconMs_=0;
    if(!result)s->wpaStateChanged(previous);
    return result;
}
void RTWUSBController::observeScanTransition(ieee80211_state previous,ieee80211_state requested,unsigned channel,int result) {
    if(requested==IEEE80211_S_SCAN)browseScanComplete_=false;
    const auto transition=requested==IEEE80211_S_SCAN?rtw::ScanDiagnosticTransition::Scan:
        requested==IEEE80211_S_AUTH?rtw::ScanDiagnosticTransition::Auth:
        requested==IEEE80211_S_INIT?rtw::ScanDiagnosticTransition::Init:rtw::ScanDiagnosticTransition::Other;
    rtw::scanDiagnosticsTransition(scanDiag_,previous==IEEE80211_S_SCAN,transition,channel,result);
    publishScanDiagnostics();
}
int RTWUSBController::scanComplete(ieee80211com*ic) {
    if(!ic||!ic->ic_softc)return 0;
    auto*core=static_cast<rtwn_softc*>(ic->ic_softc);
    auto*s=owner(core->sc_ops.cookie);
    if(!s||core!=&s->core_||ic!=&s->core_.sc_ic||!s->attached_||!s->running_||
       !s->present_||s->sleeping_||s->stopping_||s->closing_||s->joinRequested_||
       s->usbError_!=kIOReturnSuccess||core->core_error||
       s->scanDiag_.state!=rtw::ScanDiagnosticState::Active||s->scanDiag_.lastError||
       ic->ic_opmode!=IEEE80211_M_STA||ic->ic_state!=IEEE80211_S_SCAN||
       (ic->ic_flags&IEEE80211_F_BGSCAN))return 0;
    // INIT tears down the scan cache. Keep the receive state and cached BSS
    // records, but consume this completed browse sweep before JOIN retries.
    if(s->scanTimer_)s->scanTimer_->cancelTimeout();
    ic->ic_flags&=~IEEE80211_F_ASCAN;
    s->browseScanComplete_=true;
    s->scanDiag_.state=rtw::ScanDiagnosticState::Complete;
    s->scanDiag_.lastError=0;
    s->publishScanDiagnostics();
    /* Radio ABI: a scan that ended idle returns the radio to its parked
     * channel (rtlRadioSetChannel semantics). Best effort; the next sweep
     * re-parks anyway. */
    if(s->radioIdleChannel_&&ic->ic_state==IEEE80211_S_SCAN&&
       s->permits88Channel((uint8_t)s->radioIdleChannel_)&&!s->radioOffchState_)
        (void)s->set88Channel((uint8_t)s->radioIdleChannel_,false);
    return 1;
}

bool RTWUSBController::read88IdentityDescriptor(rtw_chip_identity_descriptor*out) const {
    if(!out||!usb_)return false;
    auto*device=usb_->getDevice();const auto*d=device?device->getDeviceDescriptor():nullptr;
    const auto*i=usb_->getInterfaceDescriptor();const auto*c=usb_->getConfigurationDescriptor();
    if(!d||!i||!c)return false;
    *out={USBToHost16(d->idVendor),USBToHost16(d->idProduct),USBToHost16(d->bcdDevice),
        c->bConfigurationValue,i->bInterfaceNumber,i->bInterfaceClass,i->bInterfaceSubClass,i->bInterfaceProtocol,i->bAlternateSetting};
    return true;
}
bool RTWUSBController::matches88Discovery() const {
    if(!r88ResolvedIdentity_)return true;
    rtw_chip_identity_descriptor descriptor{};
    return (const void*)r88ResolvedIdentity_==(const void*)r88IdentityStorage_&&
        usb_==r88DiscoveryProvider_&&profile_==rtw_chip_identity_profile(r88ResolvedIdentity_)&&
        profile_&&profile_->family==family_&&read88IdentityDescriptor(&descriptor)&&
        rtw_chip_identity_candidate(r88DiscoveryProfile_,&descriptor)&&
        rtw_chip_identity_descriptor_matches(r88ResolvedIdentity_,&descriptor);
}
bool RTWUSBController::permits88Transport(bool discoveryRead) const {
    if(!r88DiscoveryProvider_)return true;
    if(usb_!=r88DiscoveryProvider_)return false;
    if(!r88ResolvedIdentity_)return discoveryRead&&family_==RTW_WIFI_UNKNOWN&&profile_==r88DiscoveryProfile_;
    rtw_chip_identity_descriptor descriptor{};
    return (const void*)r88ResolvedIdentity_==(const void*)r88IdentityStorage_&&
        profile_==rtw_chip_identity_profile(r88ResolvedIdentity_)&&profile_&&profile_->family==family_&&
        read88IdentityDescriptor(&descriptor)&&rtw_chip_identity_descriptor_matches(r88ResolvedIdentity_,&descriptor);
}
bool RTWUSBController::owns88Discovery() const {
    if(!r88ResolvedIdentity_)return true;
    return (const void*)r88ResolvedIdentity_==(const void*)r88IdentityStorage_&&
        usb_==r88DiscoveryProvider_&&profile_==rtw_chip_identity_profile(r88ResolvedIdentity_)&&
        profile_&&profile_->family==family_&&rtw_chip_identity_bound_to(r88ResolvedIdentity_,&r88Core_)&&
        rtw_chip_identity_valid(r88ResolvedIdentity_,profile_,&r88Core_.raw_bus);
}
void RTWUSBController::clear88Discovery(bool forget) {
    if(!r88ResolvedIdentity_)return;
    removeProperty("RTWChipIdentityVerified");removeProperty("RTWHardwareChipCode");
    if(forget&&(const void*)r88ResolvedIdentity_==(const void*)r88IdentityStorage_)rtw_chip_identity_forget(r88ResolvedIdentity_);
    /* Keep the pointer after revocation: a failed discovery must never fall
     * back to the ordinary immutable-profile path on this controller. */
}
int RTWUSBController::prepare88Identity(const rtw88_fw_bus&bus) {
    if(!r88ResolvedIdentity_)return rtw88_boot_init(&r88Core_,profile_,&bus);
    if(!matches88Discovery()||!rtw_chip_identity_valid(r88ResolvedIdentity_,profile_,&bus)){
        clear88Discovery(true);return ENODEV;
    }
    int e=rtw88_boot_init_resolved(&r88Core_,r88ResolvedIdentity_,&bus);
    if(e)clear88Discovery(true);return e;
}
int RTWUSBController::recheck88Identity() {
    if(!r88ResolvedIdentity_)return 0;
    if(!matches88Discovery()||!owns88Discovery()){clear88Discovery(true);return ENODEV;}
    int e=rtw88_boot_revalidate_identity(&r88Core_);
    if(!e&&(!matches88Discovery()||!owns88Discovery()))e=ENODEV;
    if(e)clear88Discovery(true);return e;
}
int RTWUSBController::publish88Identity() {
    if(!r88ResolvedIdentity_)return 0;
    int e=recheck88Identity();if(e)return e;
    setProperty("RTWSiliconFamily",rtw_usb_wifi_family_name(family_));
    setProperty("RTWHardwareChipCode",(unsigned long long)rtw_chip_identity_code(r88ResolvedIdentity_),8);
    setProperty("RTWChipIdentityVerified",true);return 0;
}
bool RTWUSBController::discoverUSB() {
    IOUSBHostInterface *const discoveryProvider=usb_;
    if(!discoveryProvider)return false;
    struct ProviderReference {
        IOUSBHostInterface *const provider;
        explicit ProviderReference(IOUSBHostInterface *value):provider(value){provider->retain();}
        ~ProviderReference(){provider->release();}
    } providerReference(discoveryProvider);
    /* The interface outlives a failed Controller start. Keep discovery evidence
     * there as well so diagnostics do not require a surviving network service.
     * A callback can revoke usb_; evidence belongs to the retained original. */
    const auto stage=[&,discoveryProvider](const char *value)->bool {
        setProperty("RTWUSBDiscoveryStage",value);discoveryProvider->setProperty("RTWUSBDiscoveryStage",value);return false;
    };
    const auto fact=[&,discoveryProvider](const char *name,uint64_t value,unsigned bits=32) {
        setProperty(name,(unsigned long long)value,bits);discoveryProvider->setProperty(name,(unsigned long long)value,bits);
    };
    stage("descriptors");
    fact("RTWDiagUSBDiscoveryFailureEndpoint",0,8);
    IOUSBHostDevice *device=usb_->getDevice();
    const auto*d=device?device->getDeviceDescriptor():nullptr;
    const auto*i=usb_->getInterfaceDescriptor();const auto*c=usb_->getConfigurationDescriptor();
    if(!d||!i||!c)return stage("descriptors-unavailable");
    fact("RTWDiagUSBDiscoveryInterface",i->bInterfaceNumber,8);
    fact("RTWDiagUSBDiscoveryAlternate",i->bAlternateSetting,8);
    fact("RTWDiagUSBDiscoveryDeclaredEndpoints",i->bNumEndpoints,8);
    profile_=rtw_usb_wifi_lookup_descriptor(USBToHost16(d->idVendor),USBToHost16(d->idProduct),
        USBToHost16(d->bcdDevice),c->bConfigurationValue,i->bInterfaceNumber,
        i->bInterfaceClass,i->bInterfaceSubClass,i->bInterfaceProtocol);
    r88DiscoveryProfile_=profile_;family_=rtw_usb_wifi_station_backend(profile_);
    if(family_==RTW_WIFI_UNKNOWN){
        rtw_chip_identity_descriptor descriptor{};
        if(!read88IdentityDescriptor(&descriptor)||!rtw_chip_identity_candidate(profile_,&descriptor))return stage("identity-unverified");
        const rtw88_fw_bus bus{this,r88Read,r88Write,r88Bulk,delayUS,nullptr,nullptr};
        r88DiscoveryProvider_=usb_;
        int e=rtw_chip_identity_init(r88IdentityStorage_,sizeof(r88IdentityStorage_),profile_,&descriptor,&bus,&r88ResolvedIdentity_);
        if(e||usb_!=r88DiscoveryProvider_){clear88Discovery(true);return stage("silicon-identity");}
        profile_=rtw_chip_identity_profile(r88ResolvedIdentity_);
        if(!profile_)return stage("silicon-profile");family_=profile_->family;
        if(!matches88Discovery()){clear88Discovery(true);return stage("silicon-descriptor");}
    }
    /* Shared family registry covers every catalog chipset, but only backends
     * with an integrated station HAL may bind to an IOEthernetInterface.
     * A validated USB identity is not authorization to transmit. */
    const rtw_family_backend *backend=rtw_backend_for_family(family_);
    if(family_==RTW_WIFI_UNKNOWN||!backend||
       !(backend->capabilities&RTW_BACKEND_CAP_KEXT_STATION))return stage("station-backend");
    size_t length=USBToHost16(c->wTotalLength);
    fact("RTWDiagUSBDiscoveryConfigurationLength",length);
    if(length<9||length>4096)return stage("configuration-length");
    const auto parsed=rtw_find_usb_bulk_endpoints((const uint8_t*)c,length,i->bInterfaceNumber,i->bAlternateSetting,&endpoints_);
    fact("RTWDiagUSBDiscoveryDescriptorResult",parsed);
    fact("RTWDiagUSBDiscoveryEndpointCount",endpoints_.num_endpoints,8);
    fact("RTWDiagUSBDiscoveryBulkInCount",endpoints_.num_bulk_in,8);
    fact("RTWDiagUSBDiscoveryBulkOutCount",endpoints_.num_bulk_out,8);
    uint64_t addresses=0;
    for(unsigned p=0;p<endpoints_.num_bulk_out&&p<8;++p)addresses|=(uint64_t)endpoints_.bulk_out[p]<<(8*p);
    fact("RTWDiagUSBDiscoveryBulkOutAddresses",addresses,64);
    if(parsed!=RTW_DESC_OK)return stage("endpoint-descriptor");
    if(endpoints_.num_bulk_in!=1)return stage("bulk-in-count");
    if(endpoints_.num_bulk_out<1||endpoints_.num_bulk_out>(family_==RTW_WIFI_RTL8814AU||family_==RTW_WIFI_RTL8723BU||is8812Family()||is88Family()?4:3))return stage("bulk-out-count");
    if((family_==RTW_WIFI_RTL8814AU||is8812Family()||is88Family())&&endpoints_.num_bulk_out<2)return stage("bulk-out-minimum");
    fact("RTWDiagUSBDiscoveryFailureEndpoint",endpoints_.bulk_in[0],8);
    rxPipe_=usb_->copyPipe(endpoints_.bulk_in[0]);if(!rxPipe_)return stage("bulk-in-pipe");
    for(unsigned p=0;p<endpoints_.num_bulk_out;p++) {
        fact("RTWDiagUSBDiscoveryFailureEndpoint",endpoints_.bulk_out[p],8);
        txPipes_[p]=usb_->copyPipe(endpoints_.bulk_out[p]);if(!txPipes_[p])return stage("bulk-out-pipe");
        const auto*e=txPipes_[p]->getEndpointDescriptor();if(!e)return stage("bulk-out-descriptor");
        txMPS_[p]=USBToHost16(e->wMaxPacketSize)&0x7ff;
        fact("RTWDiagUSBDiscoveryMaxPacket",txMPS_[p],16);
        if(txMPS_[p]!=64&&txMPS_[p]!=512&&!((family_==RTW_WIFI_RTL8814AU||is8812Family()||is88Family())&&txMPS_[p]==1024))return stage("bulk-out-max-packet");
    }
    core_.ac2idx[EDCA_AC_BK]=core_.ac2idx[EDCA_AC_BE]=endpoints_.num_bulk_out>=3?2:endpoints_.num_bulk_out==2?1:0;
    core_.ac2idx[EDCA_AC_VI]=endpoints_.num_bulk_out>=3?1:0;core_.ac2idx[EDCA_AC_VO]=0;
    fact("RTWDiagUSBDiscoveryFailureEndpoint",0,8);stage("ready");
    return true;
}
IOReturn RTWUSBController::initializePlatform() {
    reportStartStage("usb-discovery");
    if(!discoverUSB()){reportStartStage("usb-discovery",kIOReturnUnsupported);return kIOReturnUnsupported;}
    core_.chip=RTWN_CHIP_USB;core_.sc_flags=0;
    if(family_==RTW_WIFI_RTL8192EU){core_.chip|=RTWN_CHIP_92E;core_.sc_flags=RTWN_FLAG_EXT_HDR;}
    else if(family_==RTW_WIFI_RTL8188EU)core_.chip|=RTWN_CHIP_88E;
    else if(family_==RTW_WIFI_RTL8192CU)core_.chip|=RTWN_CHIP_92C|RTWN_CHIP_88C;
    else if(family_!=RTW_WIFI_RTL8814AU&&!is8812Family()&&!is88Family()&&family_!=RTW_WIFI_RTL8192DU&&family_!=RTW_WIFI_RTL8192FU&&family_!=RTW_WIFI_RTL8710BU&&family_!=RTW_WIFI_RTL8723BU)return kIOReturnUnsupported;
    setProperty("RTWSiliconFamily",rtw_usb_wifi_family_name(family_));
    rtwn_ops&o=core_.sc_ops;o.cookie=this;o.delay_us=delayUS;o.write_region=writeRegion;o.io_error=ioError;
    o.read_1=read1;o.read_2=read2;o.read_4=read4;o.write_1=write1;o.write_2=write2;o.write_4=write4;
    o.tx=transmit;o.power_on=busPower;o.dma_init=busDMA;o.fw_loadpage=busFirmware;o.load_firmware=loadFirmware;
    o.mac_init=busMAC;o.bb_init=busBB;o.aggr_init=busAggregation;o.alloc_buffers=busAllocate;o.init=busInitialize;
    o.stop=busStop;o.is_oactive=busBusy;o.next_scan=nextScan;o.cancel_scan=cancelScan;
    o.next_calib=nextCalibration;o.cancel_calib=cancelCalibration;o.wait_async=waitAsync;
    device_.provider=usb_;device_._data=this;strlcpy(device_.dv_xname,rtw_usb_wifi_family_name(family_),sizeof(device_.dv_xname));
    reportStartStage("rtwn-attach");
    int result=is8723Family()?attach8723():is8710BUFamily()?attach8710BU():is8192FUFamily()?attach8192FU():family_==RTW_WIFI_RTL8192DU?attach8192DU():is88Family()?attach88():is8812Family()?attach8812():family_==RTW_WIFI_RTL8814AU?attach8814():rtwn_attach(&device_,&core_,this);
    if(result){reportStartStage("rtwn-attach",fromErrno(result));return fromErrno(result);}
    attached_=true;
    const int recoveryIdentity=captureFamilyRecoveryIdentity();
    if(recoveryIdentity)return fromErrno(recoveryIdentity);
    bool nonzero=false;for(unsigned n=0;n<6;n++)nonzero|=core_.sc_ic.ic_myaddr[n]!=0;
    if(!nonzero||(core_.sc_ic.ic_myaddr[0]&1)||rtwn_io_error(&core_)){reportStartStage("efuse-mac",kIOReturnIOError);return kIOReturnIOError;}
    memcpy(mac_.bytes,core_.sc_ic.ic_myaddr,6);macReady_=true;
    core_.sc_ic.ic_newstate=stateTransition;core_.sc_ic.ic_scan_done=scanComplete;core_.sc_ic.ic_max_rssi=100;
    core_.sc_ic.ic_ampdu_rx_start=family_==RTW_WIFI_RTL8192DU?ampdu8192DURXStart:ampduRXStart;core_.sc_ic.ic_ampdu_rx_stop=family_==RTW_WIFI_RTL8192DU?ampdu8192DURXStop:ampduRXStop;
    core_.sc_ic.ic_ampdu_tx_start=ampduTXStart;core_.sc_ic.ic_ampdu_tx_stop=ampduTXStop;
    core_.sc_ic.ic_flags&=~IEEE80211_F_AUTO_JOIN;
    super::setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}
int RTWUSBController::allocateTransfers() {
    if(!completionLock_)return ENXIO;
    for(unsigned i=0;i<RTW_TRANSFER_SLOTS;i++) {
        Transfer&t=transfers_[i];t.owner=this;t.index=i;
        const uint32_t capacity=i<RXSlots?rtw_usb_rx_capacity(family_):TXCapacity;
        if(!t.memory)t.memory=IOBufferMemoryDescriptor::withCapacity(capacity,i<RXSlots?kIODirectionIn:kIODirectionOut);
        if(!t.memory||t.memory->getCapacity()<capacity||!t.memory->getBytesNoCopy()){freeTransfers();return ENOMEM;}
    }
    return 0;
}
void RTWUSBController::freeTransfers() {
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    bool drained=rtw_transfer_drained(&ledger_);IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(!drained)return;
    for(auto&t:transfers_) {if(t.prepared&&t.memory){t.memory->complete();t.prepared=false;}if(t.memory){t.memory->release();t.memory=nullptr;}t.pipe=nullptr;}
}
bool RTWUSBController::hasFreeTX() const {
    if(!running_||stopping_||!present_||usbError_!=kIOReturnSuccess)return false;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);bool available=false;
    for(unsigned i=RXSlots;i<RTW_TRANSFER_SLOTS;i++)if(!(ledger_.pending&(1U<<i))){available=true;break;}
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);return available;
}
int RTWUSBController::submit(unsigned index,IOUSBHostPipe*pipe,uint32_t length) {
    if(index>=RTW_TRANSFER_SLOTS||!running_||stopping_||!present_||sleeping_||usbError_!=kIOReturnSuccess||!pipe)return ENXIO;
    if(index<RXSlots&&rxRecovery_.pending&&!rxRecovery_.refilling)return EBUSY;
    Transfer&t=transfers_[index];if(!t.memory||length>t.memory->getCapacity())return EINVAL;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    bool accepted=rtw_transfer_begin(&ledger_,index);
    if(accepted&&++t.generation==0)++t.generation;
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(!accepted)return EBUSY;
    t.pipe=pipe;t.submitted=length;t.actual=0;t.result=kIOReturnNotReady;
    retain(); /* released only after completion is recorded and reclaimed */
    IOReturn result=t.memory->prepare();
    bool transientRXRejection=false;
    if(result==kIOReturnSuccess){
        t.prepared=true;IOUSBHostCompletion completion{this,usbCompletion,(void*)(((uintptr_t)t.generation<<4)|index)};
        result=pipe->io(t.memory,length,&completion,index<RXSlots?0:1000);
        transientRXRejection=index<RXSlots&&result==kIOReturnNotResponding;
    }
    if(result!=kIOReturnSuccess){
        /* A failed recovery must retain the original transaction error,
         * rather than replacing it with the refill's secondary error. */
        if(index<RXSlots&&rxRecovery_.refilling)rxRecovery_.lastError=result;
        else if(!transientRXRejection)fault(result);
        /* A halted pipe can reject io() before accepting a callback. Record
         * that zero-byte result just like an asynchronous RX completion. A
         * prepare() failure never enters this transport recovery path. */
        recordCompletion(&t,result,0,t.generation);return transientRXRejection?EAGAIN:EIO;
    }
    return 0;
}
bool RTWUSBController::beginRXRecovery(IOReturn error) {
    const auto*backend=rtw_backend_for_family(family_);
    if(!backend||!(backend->capabilities&RTW_BACKEND_CAP_KEXT_STATION)||error!=kIOReturnNotResponding||
       !attached_||!running_||stopping_||sleeping_||closing_||!present_||
       usbError_!=kIOReturnSuccess||core_.core_error||!rxPipe_||!watchdogTimer_||rxRecovery_.pending)return false;
    auto&r=rxRecovery_;
    ++r.errors;r.lastError=error;r.originalError=error;
    if(!r.endpoint)r.endpoint=endpoints_.bulk_in[0];
    if(r.consecutive>=3){++r.failures;++r.exhausted;r.failureStage=RXRecovery::Idle;r.stage=RXRecovery::Failed;return false;}
    ++r.consecutive;++r.attempts;r.startedMS=nowMS();
    r.nextAttemptMS=0;r.clearAttempt=0;r.refillSlot=RXSlots;
    r.clearResult=r.refillResult=kIOReturnSuccess;r.failureStage=RXRecovery::Idle;r.stage=RXRecovery::Clear;
    r.pending=true;r.cleared=false;r.refilling=false;
    watchdogTimer_->setTimeoutMS(100);
    return true;
}
void RTWUSBController::failRXRecovery(bool exhausted) {
    auto&r=rxRecovery_;
    ++r.failures;if(exhausted)++r.exhausted;
    r.failureStage=r.stage;r.stage=RXRecovery::Failed;r.nextAttemptMS=0;
    r.pending=r.cleared=r.refilling=false;
    fault(r.originalError);
    if(attached_&&!stopping_)quiesce(false);
}
void RTWUSBController::advanceRXRecovery() {
    auto&r=rxRecovery_;
    if(!r.pending)return;
    if(!running_||stopping_||sleeping_||closing_||!present_||usbError_!=kIOReturnSuccess||core_.core_error){
        r.pending=r.cleared=r.refilling=false;r.stage=RXRecovery::Cancelled;r.nextAttemptMS=0;return;
    }
    if(nowMS()-r.startedMS>=2000){r.lastError=kIOReturnTimeout;failRXRecovery();return;}
    if(r.nextAttemptMS&&nowMS()<r.nextAttemptMS)return;
    r.nextAttemptMS=0;
    auto retryTransient=[&]{
        r.refilling=false;
        if(nowMS()-r.startedMS>=2000){r.lastError=kIOReturnTimeout;failRXRecovery();return;}
        if(r.clearAttempt>=3){++r.transportExhausted;failRXRecovery();return;}
        ++r.transportRetries;r.cleared=false;r.stage=RXRecovery::RetryWait;
        r.nextAttemptMS=nowMS()+100;
        watchdogTimer_->setTimeoutMS(100);
    };
    if(!r.cleared){
        /* IOUSBHostPipe halts after a non-timeout bulk error. clearStall(true)
         * synchronizes device/host toggles and aborts the other old RX reads.
         * Their callbacks only record completions; never refill in this call. */
        r.stage=RXRecovery::Clear;++r.clearAttempt;++r.clearAttempts;
        IOReturn result=rxPipe_->clearStall(true);
        r.clearResult=result;
        if(result!=kIOReturnSuccess){
            ++r.clearFailures;r.lastError=result;
            if(result==kIOReturnNotResponding)retryTransient();else failRXRecovery();
            return;
        }
        if(nowMS()-r.startedMS>=2000){r.lastError=kIOReturnTimeout;failRXRecovery();return;}
        r.cleared=true;
    }
    r.stage=RXRecovery::Drain;
    const uint32_t rxMask=(1U<<RXSlots)-1U;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    bool drained=(ledger_.pending&rxMask)==0;
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(!drained)return;
    r.refilling=true;r.stage=RXRecovery::Refill;
    for(unsigned i=0;i<RXSlots;i++){
        r.refillSlot=i;
        int error=submit(i,rxPipe_,rtw_usb_rx_capacity(family_));
        if(error){
            ++r.refillFailures;r.refillResult=r.lastError;r.refilling=false;
            /* Some reads in this refill may already be accepted or complete.
             * A fresh clear/drain must discard the entire partial epoch before
             * any slot is reused; the whole recovery retains its deadline. */
            if(error==EAGAIN)retryTransient();else failRXRecovery();
            return;
        }
        r.refillResult=kIOReturnSuccess;
        if(nowMS()-r.startedMS>=2000){r.lastError=kIOReturnTimeout;r.refilling=false;failRXRecovery();return;}
    }
    r.pending=r.cleared=r.refilling=false;r.stage=RXRecovery::Complete;++r.completed;
}
void RTWUSBController::publishRXRecoveryDiagnostics() {
    auto publish=[this](const char*name,uint64_t value){publishDiagnosticCounter(name,value);};
    const auto&r=rxRecovery_;
    publish("RTWDiagRXInitialErrors",r.initialErrors);
    publish("RTWDiagRXInitialClearAttempts",r.initialClearAttempts);
    publish("RTWDiagRXInitialFailures",r.initialFailures);
    publish("RTWDiagRXInitialExhausted",r.initialExhausted);
    publish("RTWDiagRXInitialConsecutive",r.initialConsecutive);
    publish("RTWDiagRXInitialOriginalError",(uint32_t)r.initialOriginalError);
    publish("RTWDiagRXInitialClearResult",(uint32_t)r.initialClearResult);
    publish("RTWDiagRXInitialDrainMask",r.initialDrainMask);
    publish("RTWDiagRXInitialDrainError",(uint32_t)r.initialDrainError);
    publish("RTWDiagUSBStopDrainMask",r.stopDrainMask);
    publish("RTWDiagUSBStopDrainError",(uint32_t)r.stopDrainError);
    publish("RTWDiagUSBStopDrainFailures",r.stopDrainFailures);
    publish("RTWDiagRXRecoveryErrors",r.errors);publish("RTWDiagRXRecoveryAttempts",r.attempts);
    publish("RTWDiagRXRecoveryCompleted",r.completed);publish("RTWDiagRXRecoveryFailures",r.failures);
    publish("RTWDiagRXRecoveryExhausted",r.exhausted);publish("RTWDiagRXRecoveryPending",r.pending?1:0);
    publish("RTWDiagRXRecoveryConsecutive",r.consecutive);publish("RTWDiagRXRecoveryEndpoint",r.endpoint);
    publish("RTWDiagRXRecoveryOriginalError",(uint32_t)r.originalError);
    publish("RTWDiagRXRecoveryLastError",(uint32_t)r.lastError);
    publish("RTWDiagRXRecoveryStage",r.stage);publish("RTWDiagRXRecoveryFailureStage",r.failureStage);
    publish("RTWDiagRXRecoveryClearResult",(uint32_t)r.clearResult);
    publish("RTWDiagRXRecoveryRefillResult",(uint32_t)r.refillResult);
    publish("RTWDiagRXRecoveryClearAttempts",r.clearAttempts);publish("RTWDiagRXRecoveryClearAttempt",r.clearAttempt);
    publish("RTWDiagRXRecoveryClearFailures",r.clearFailures);publish("RTWDiagRXRecoveryRefillFailures",r.refillFailures);
    publish("RTWDiagRXRecoveryTransportRetries",r.transportRetries);publish("RTWDiagRXRecoveryTransportExhausted",r.transportExhausted);
    publish("RTWDiagRXRecoveryRefillSlot",r.refillSlot);
}
void RTWUSBController::recordCompletion(Transfer*t,IOReturn result,uint32_t length,uint32_t generation) {
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    if(t->generation==generation&&rtw_transfer_complete(&ledger_,t->index)){t->result=result;t->actual=length;}
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(completionEvent_)completionEvent_->interruptOccurred(nullptr,nullptr,0);
}
void RTWUSBController::usbCompletion(void*owner,void*parameter,IOReturn result,uint32_t length) {
    auto*s=static_cast<RTWUSBController*>(owner);
    uintptr_t token=(uintptr_t)parameter;unsigned index=(unsigned)(token&15);
    if(s&&index<RTW_TRANSFER_SLOTS)s->recordCompletion(&s->transfers_[index],result,length,(uint32_t)(token>>4));
}
void RTWUSBController::completionAction(OSObject*owner,IOInterruptEventSource*,int) { static_cast<RTWUSBController*>(owner)->drainCompletions(true); }
void RTWUSBController::serviceTXOutputQueue() {
    if(closing_||stopping_||!authorized())return;
    auto*pending=core_.sc_ic.ic_if.if_snd.queue;
    if(!pending||pending->getSize()>=pending->getCapacity())return;
    // The completion path holds the workloop gate. Defer the outer queue's
    // retry rather than reenter its dequeue/locking path synchronously.
    if(auto*queue=getOutputQueue())queue->service(IOBasicOutputQueue::kServiceAsync);
}
void RTWUSBController::drainCompletions(bool process) {
    retain();bool failure=false,rxRecoveryFatal=false;
    auto validateStopped=[&](unsigned i)->IOReturn {
        auto&r=rxRecovery_;const uint32_t bit=1U<<i;const auto&t=transfers_[i];
        const bool initial=i<RXSlots&&(r.initialDrainMask&bit);
        const bool stopped=(r.stopDrainMask&bit)!=0;
        if(!initial&&!stopped)return kIOReturnSuccess;
        IOReturn error=kIOReturnSuccess;
        if((initial&&t.generation!=r.initialDrainGeneration[i])||
           (stopped&&t.generation!=r.stopDrainGeneration[i]))error=kIOReturnIOError;
        else if(t.actual>t.submitted||(i>=RXSlots&&t.result==kIOReturnSuccess&&t.actual!=t.submitted))error=kIOReturnUnderrun;
        else if(t.result!=kIOReturnSuccess&&t.result!=kIOReturnAborted&&
                !(initial&&t.result==kIOReturnNotResponding&&!t.actual))error=t.result;
        if(initial){
            r.initialDrainMask&=~bit;
            if(error!=kIOReturnSuccess&&r.initialDrainError==kIOReturnSuccess){
                r.initialDrainError=error;++r.initialFailures;
            }
        }
        if(stopped){
            r.stopDrainMask&=~bit;
            if(error!=kIOReturnSuccess){
                if(r.stopDrainError==kIOReturnSuccess)r.stopDrainError=error;
                ++r.stopDrainFailures;
            }
        }
        if(error!=kIOReturnSuccess){
            if(i<RXSlots)++rxErrors_;
            else{++txErrors_;++txUSBTransferErrors_;if(stats_)++stats_->outputErrors;}
        }
        return error;
    };
    if(rxRecovery_.initialDrainMask||rxRecovery_.stopDrainMask){
        IOReturn firstFault=kIOReturnSuccess;
        /* Detect a fatal callback even behind an older payload-order hole.
         * Lifecycle cancellation cannot erase a real transport failure. */
        IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
        for(unsigned i=0;i<RTW_TRANSFER_SLOTS;++i)if(ledger_.completed&(1U<<i)){
            const auto error=validateStopped(i);
            if(firstFault==kIOReturnSuccess)firstFault=error;
        }
        IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
        if(firstFault!=kIOReturnSuccess)fault(firstFault);
    }
    /* A watchdog-queued common-core reinit also finishes with IFF_RUNNING.
     * This handler cannot interleave with that gate-held initialization. */
    if(running_&&(core_.sc_ic.ic_if.if_flags&IFF_RUNNING)&&!rtwn_io_error(&core_))radioReady_=enabled_=true;
    if(process&&running_&&!rxRecovery_.pending){
        /* An endpoint error can complete behind an older RX callback hole.
         * Inspect only completion metadata here: waiting for ordered payload
         * delivery could otherwise prevent both halt clearing and its timer. */
        bool transactionError=false;
        IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
        for(unsigned i=0;i<RXSlots;i++)if((ledger_.completed&(1U<<i))&&
           transfers_[i].result==kIOReturnNotResponding&&!transfers_[i].actual){transactionError=true;break;}
        IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
        if(transactionError){
            ++rxErrors_;
            if(!beginRXRecovery(kIOReturnNotResponding)){
                failure=rxRecoveryFatal=true;fault(kIOReturnNotResponding);
            }
        }
    }
    auto reclaim=[&](unsigned i){
        Transfer&t=transfers_[i];
        /* A completion can arrive after preflight but before take(). Its
         * slot is stable after take, so validate again before releasing it. */
        const auto stoppedFault=validateStopped(i);
        if(stoppedFault!=kIOReturnSuccess)fault(stoppedFault);
        if(t.prepared){t.memory->complete();t.prepared=false;}
        bool success=t.result==kIOReturnSuccess&&t.actual<=t.submitted;
        if(i>=RXSlots)success=success&&t.actual==t.submitted;
        if(i<RXSlots){
            /* Clearing a halt may cancel the other old reads. Only those
             * cancellations and the same zero-byte transaction error belong
             * to this recovery; never hide a different coalesced RX fault. */
            if(process&&running_&&rxRecovery_.pending&&!success&&t.result!=kIOReturnAborted&&
               !(t.result==kIOReturnNotResponding&&!t.actual)){
                ++rxErrors_;failure=true;fault(t.result==kIOReturnSuccess?kIOReturnUnderrun:t.result);
            }
            if(process&&running_&&!failure&&!rxRecoveryFatal&&!rxRecovery_.pending&&success&&t.actual){
                const uint64_t before=rxPackets_;
                receive((const uint8_t*)t.memory->getBytesNoCopy(),t.actual);
                /* Empty/malformed transfers cannot replenish the retry budget. */
                if(rxPackets_>before)rxRecovery_.consecutive=0;
            }
            if(process&&running_&&!rxRecoveryFatal&&!rxRecovery_.pending&&!success&&t.result!=kIOReturnAborted){
                rxErrors_++;
                if(t.actual||!beginRXRecovery(t.result)){failure=true;fault(t.result==kIOReturnSuccess?kIOReturnUnderrun:t.result);}
            }
        }else{
            if(success){txPackets_++;if(stats_)stats_->outputPackets++;core_.sc_tx_timer=0;}
            else if(process&&running_&&t.result!=kIOReturnAborted){
                txErrors_++;txUSBTransferErrors_++;if(stats_)stats_->outputErrors++;
                failure=true;fault(t.result==kIOReturnSuccess?kIOReturnUnderrun:t.result);
            }
        }
        t.pipe=nullptr;
        if(i<RXSlots&&process&&running_&&!stopping_&&!failure&&!rxRecovery_.pending&&usbError_==kIOReturnSuccess){
            int error=submit(i,rxPipe_,rtw_usb_rx_capacity(family_));
            if(error==EAGAIN){
                ++rxErrors_;
                if(!beginRXRecovery(kIOReturnNotResponding)){failure=true;fault(kIOReturnNotResponding);}
            }else if(error){failure=true;fault(kIOReturnIOError);}
        }
        release();
    };
    const uint32_t rxMask=(1U<<RXSlots)-1U;
    unsigned rxProcessed=0;
    if(process&&!rxRecovery_.pending){
        /* A recycled low-numbered slot follows older endpoint reads. Retain
         * submission order even when callbacks are delayed or coalesced. */
        while(rxProcessed<RXSlots){
            unsigned i=0;
            IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
            bool done=rtw_transfer_take_oldest(&ledger_,rxMask,&i);
            IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
            if(!done)break;
            ++rxProcessed;reclaim(i);
            if(rxRecovery_.pending)break;
        }
    }else{
        /* Abort cleanup must reclaim completed reads despite a callback hole. */
        for(unsigned i=0;i<RXSlots;i++){
            IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
            bool done=rtw_transfer_take(&ledger_,i);
            IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
            if(done)reclaim(i);
        }
    }
    for(unsigned i=RXSlots;i<RTW_TRANSFER_SLOTS;i++){
        IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
        bool done=rtw_transfer_take(&ledger_,i);
        IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
        if(done)reclaim(i);
    }
    if(process&&!rxRecovery_.pending&&rxProcessed==RXSlots&&running_&&!stopping_&&!failure){
        IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
        bool ready=rtw_transfer_oldest_ready(&ledger_,rxMask);
        IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
        if(ready&&completionEvent_)completionEvent_->interruptOccurred(nullptr,nullptr,0);
    }
    if(failure&&attached_&&!stopping_){
        if(rxRecovery_.pending){rxRecovery_.lastError=usbError_;failRXRecovery();}
        else quiesce(false);
    }
    if(process&&rxRecovery_.pending)advanceRXRecovery();
    if(process&&running_&&!stopping_&&hasFreeTX()){
        ifq_clr_oactive(&core_.sc_ic.ic_if.if_snd);rtwn_start(&core_.sc_ic.ic_if);
        serviceTXOutputQueue();
    }
    if(family_==RTW_WIFI_RTL8814AU)finish8814StopAfterDrain();
    else finishFamilyStopAfterDrain();
    scheduleDeferredCleanup();
    release();
}
void RTWUSBController::abortTransfers() {
    running_=false;radioReady_=false;rateTransportFresh_=false;
    if(rxRecovery_.pending)rxRecovery_.stage=RXRecovery::Cancelled;
    rxRecovery_.nextAttemptMS=0;
    rxRecovery_.pending=rxRecovery_.cleared=rxRecovery_.refilling=false;
    cancelWpaRecovery();
    if(scanTimer_)scanTimer_->cancelTimeout();if(calibTimer_)calibTimer_->cancelTimeout();if(watchdogTimer_)watchdogTimer_->cancelTimeout();
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    /* Startup rollback owns its eligible zero-byte RX error separately. */
    const uint32_t stopped=ledger_.pending&~rxRecovery_.initialDrainMask;
    for(unsigned i=0;i<RTW_TRANSFER_SLOTS;++i)if((stopped&(1U<<i))&&!(rxRecovery_.stopDrainMask&(1U<<i))){
        rxRecovery_.stopDrainGeneration[i]=transfers_[i].generation;
        rxRecovery_.stopDrainMask|=1U<<i;
    }
    rtw_transfer_stop(&ledger_);IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(rxPipe_)rxPipe_->abort(IOUSBHostIOSource::kAbortSynchronous);
    for(auto*p:txPipes_)if(p)p->abort(IOUSBHostIOSource::kAbortSynchronous);
    drainCompletions(false);
}
void RTWUSBController::resetRateControl() {
    auto&r=rateControl_;
    /* CCX has no JOIN generation or 802.11 sequence/tag. Once this
     * association requested a report, only a complete firmware/DMA/USB
     * restart can certify an empty previous transport epoch. */
    if(r.requestedSinceReset)rateTransportFresh_=false;
    r.requestedSinceReset=false;r.pendingReports=0;r.active=false;r.seenSequence=false;
    r.policy.amrr_min_success_threshold=1;r.policy.amrr_max_success_threshold=15;
    ieee80211_amrr_node_init(&r.policy,&r.node);++r.resets;
    memset(r.bssid,0,sizeof(r.bssid));r.finalRate=0;
    auto*node=core_.sc_ic.ic_bss;
    r.hostHTCount=r.hostHTIndex=0;memset(r.hostHTRates,0,sizeof(r.hostHTRates));
    if(family_==RTW_WIFI_RTL8188EU&&usesLegacyHighThroughput()) {
        /* HT20 long-GI throughput order; SGI moves MCS5 above OFDM54.
         * Every candidate is intersected with the AP's actual rate mask. */
        uint8_t order[20]={0,1,2,4,12,5,3,6,13,7,14,8,15,9,16,10,17,11,18,19};
        if(core_.rate_config.sgi20){order[16]=11;order[17]=17;}
        bool initial=false;
        for(auto hw:order)if(core_.rate_config.rate_mask&(1U<<hw)) {
            if(!initial&&hw>=12){r.hostHTIndex=r.hostHTCount;initial=true;}
            r.hostHTRates[r.hostHTCount++]=hw;
        }
    }
    if(node){
        if(family_!=RTW_WIFI_RTL8192CU&&family_!=RTW_WIFI_RTL8814AU&&!is8812Family()&&!is88Family()&&family_!=RTW_WIFI_RTL8192DU&&family_!=RTW_WIFI_RTL8192FU&&family_!=RTW_WIFI_RTL8710BU&&family_!=RTW_WIFI_RTL8723BU)node->ni_txrate=0;
        IEEE80211_ADDR_COPY(r.bssid,node->ni_bssid);
        r.active=family_!=RTW_WIFI_RTL8192CU&&family_!=RTW_WIFI_RTL8814AU&&!is8812Family()&&!is88Family()&&family_!=RTW_WIFI_RTL8192DU&&family_!=RTW_WIFI_RTL8192FU&&family_!=RTW_WIFI_RTL8710BU&&family_!=RTW_WIFI_RTL8723BU&&running_&&!stopping_&&rateTransportFresh_&&core_.sc_ic.ic_state==IEEE80211_S_RUN;
    }
}
void RTWUSBController::handleTxReport(const uint8_t*bytes,size_t length) {
    auto&r=rateControl_;auto*node=core_.sc_ic.ic_bss;
    if(!running_||stopping_||!authorized()||core_.sc_ic.ic_state!=IEEE80211_S_RUN||
       !node||!r.active||!rateTransportFresh_||!IEEE80211_ADDR_EQ(r.bssid,node->ni_bssid)||
       !r.pendingReports){++r.ignored;return;}
    rtw_92e_tx_report report{};bool packetOK=true;
    if(family_==RTW_WIFI_RTL8188EU){
        rtw_88e_tx_report legacy{};
        if(!rtw_88e_parse_tx_report(bytes,length,&legacy)){++r.invalid;return;}
        report=legacy.report;packetOK=legacy.packet_ok;
    }else if(family_==RTW_WIFI_RTL8192EU){
        if(bytes&&length&&bytes[0]!=3U){++r.ignored;return;}
        if(!rtw_92e_parse_tx_report(bytes,length,&report)){++r.invalid;return;}
    }else {++r.ignored;return;}
    /* The C2H sequence is not a per-MPDU tag. Repeated values are legal
     * feedback candidates, bounded by this epoch's pending SPE requests. */
    if(family_==RTW_WIFI_RTL8192EU&&r.seenSequence&&r.lastSequence==report.event_sequence)++r.repeatedSequences;
    static const uint8_t values[12]={2,4,11,22,12,18,24,36,48,72,96,108};
    bool negotiated=false;
    if(usesFirmwareRate()||(family_==RTW_WIFI_RTL8188EU&&usesLegacyHighThroughput()))negotiated=(core_.rate_config.rate_mask & (1U<<report.final_rate))!=0;
    if(report.final_rate<12 && node->ni_rates.rs_nrates<=nitems(node->ni_rates.rs_rates))
        for(unsigned i=0;i<node->ni_rates.rs_nrates;i++)
            if((node->ni_rates.rs_rates[i]&IEEE80211_RATE_VAL)==values[report.final_rate])negotiated=true;
    if(!negotiated){++r.invalid;return;}
    r.seenSequence=true;r.lastSequence=report.event_sequence;r.finalRate=report.final_rate;
    --r.pendingReports;++r.reports;
    bool failed=!packetOK||report.lifetime_expired||report.retry_over;
    if(failed)++r.failures;
    /* Count RF report outcomes, never USB completions. A failed packet with
     * zero retries is still a failed AMRR sample, not a clean success. */
    if(report.retries||failed)++r.retried;
    if(!usesFirmwareRate()){
        if(r.node.amn_txcnt<~0U)++r.node.amn_txcnt;
        if((report.retries||failed)&&r.node.amn_retrycnt<~0U)++r.node.amn_retrycnt;
    }
}
void RTWUSBController::chooseRateControl() {
    auto&r=rateControl_;auto*node=core_.sc_ic.ic_bss;
    if(family_==RTW_WIFI_RTL8188EU&&usesLegacyHighThroughput()&&authorized()&&
       r.active&&rateTransportFresh_&&IEEE80211_ADDR_EQ(r.bssid,node->ni_bssid)&&
       r.hostHTCount&&r.hostHTIndex<r.hostHTCount) {
        uint8_t previous=r.hostHTIndex;
        ieee80211_amrr_choose_index(&r.policy,&r.hostHTIndex,r.hostHTCount,&r.node);
        if(previous!=r.hostHTIndex)++r.changes;
    } else if(!usesLegacyHighThroughput()&&!usesFirmwareRate()&&!usesLegacyFirmwareRate()&&!uses8814FirmwareRate()&&!is8812Family()&&!is88Family()&&family_!=RTW_WIFI_RTL8192DU&&family_!=RTW_WIFI_RTL8192FU&&family_!=RTW_WIFI_RTL8710BU&&family_!=RTW_WIFI_RTL8723BU&&running_&&!stopping_&&authorized()&&core_.sc_ic.ic_state==IEEE80211_S_RUN&&
       node&&r.active&&rateTransportFresh_&&IEEE80211_ADDR_EQ(r.bssid,node->ni_bssid)&&
       node->ni_rates.rs_nrates&&node->ni_rates.rs_nrates<=nitems(node->ni_rates.rs_rates)&&
       node->ni_txrate<node->ni_rates.rs_nrates){
        uint8_t previous=node->ni_txrate;
        ieee80211_amrr_choose(&r.policy,node,&r.node);
        if(node->ni_txrate!=previous)++r.changes;
    }
    publishRateControlDiagnostics();
}
void RTWUSBController::publishRateControlDiagnostics() {
    /* Observer only. STATUS must never run AMRR, touch USB or select a rate.
     * The native backends return from calibAction before its AMRR branch. */
    const auto&r=rateControl_;const auto*node=core_.sc_ic.ic_bss;
    const bool associated=running_&&!stopping_&&core_.sc_ic.ic_state==IEEE80211_S_RUN&&node;
    uint64_t selected=0;
    if(associated&&node->ni_rates.rs_nrates<=nitems(node->ni_rates.rs_rates)&&node->ni_txrate<node->ni_rates.rs_nrates)
        selected=node->ni_rates.rs_rates[node->ni_txrate]&IEEE80211_RATE_VAL;
    if(usesFirmwareRate()||usesLegacyFirmwareRate()||uses8814FirmwareRate()||uses8812FirmwareRate()||uses88FirmwareRate()||uses8192DUFirmwareRate()||uses8192FUFirmwareRate()||uses8710BUFirmwareRate()||uses8723FirmwareRate())selected=0;
    const bool legacyHT=usesLegacyHighThroughput();
    if(legacyHT&&family_==RTW_WIFI_RTL8188EU) {
        const uint8_t hw=legacyHostHTRate();
        static const uint8_t legacy[12]={2,4,11,22,12,18,24,36,48,72,96,108};
        static const uint8_t lgi[8]={13,26,39,52,78,104,117,130};
        static const uint8_t sgi[8]={14,29,43,58,87,116,130,144};
        selected=hw<12?legacy[hw]:hw<20?(core_.rate_config.sgi20?sgi[hw-12]:lgi[hw-12]):0;
    }
    publishDiagnosticCounter("RTWDiagFirmwareRateControl",(uint64_t)(usesFirmwareRate()||usesLegacyFirmwareRate()||uses8814FirmwareRate()||uses8812FirmwareRate()||uses88FirmwareRate()||uses8192DUFirmwareRate()||uses8192FUFirmwareRate()||uses8710BUFirmwareRate()||uses8723FirmwareRate()));
    publishDiagnosticCounter("RTWDiagSiliconFamily",(uint64_t)family_);
    publishDiagnosticCounter("RTWDiagTXRate500Kbps",selected);
    const auto* hwRate=associated&&uses88FirmwareRate()?&r88Rates_.rates:associated&&uses8814FirmwareRate()?&acRateConfig_:nullptr;
    const bool r88HT=associated&&uses88FirmwareRate()&&r88Rates_.rates.ht;
    const bool acHT=hwRate&&hwRate->ht,auHT=associated&&uses8812HighThroughput();
    const bool auVHT=auHT&&auRateConfig_.vht;
    const bool r88VHT=r88HT&&r88Rates_.vht;
    const bool duHT=associated&&uses8192DUFirmwareRate()&&duMAC_.rates.ht,fuHT=associated&&uses8192FUHighThroughput(),buHT=associated&&uses8710BUHighThroughput(),r23HT=associated&&uses8723FirmwareRate()&&(r23Rates_.mask&0xff000U);
    const bool htNegotiated=usesFirmwareRate()||legacyHT||acHT||auHT||duHT||fuHT||buHT||r23HT;
    publishDiagnosticCounter("RTWDiagHTNegotiated",(uint64_t)htNegotiated);
    publishDiagnosticCounter("RTWDiagVHTNegotiated",(uint64_t)(auVHT||r88VHT));
    publishDiagnosticCounter("RTWDiagHTRateMask",htNegotiated?(uint64_t)(r23HT?r23Rates_.mask:buHT?buRate_.mask:fuHT?fuRate_.mask:duHT?duMAC_.rates.mask:auHT?auRateConfig_.mask:acHT?hwRate->mask:core_.rate_config.rate_mask):0);
    publishDiagnosticCounter("RTWDiagHTSGI20Negotiated",(uint64_t)(((usesFirmwareRate()||legacyHT)&&core_.rate_config.sgi20)||(r23HT&&r23Rates_.sgi)||(buHT&&buRate_.width_mhz==20&&buRate_.sgi)||(fuHT&&fuRate_.width_mhz==20&&fuRate_.sgi)||(duHT&&duMAC_.rates.sgi20)||(acHT&&(!r88HT||r88Rates_.width_mhz==20)&&hwRate->sgi20)||(auHT&&auRateConfig_.bandwidth_mhz==20&&auRateConfig_.short_gi)));
    publishDiagnosticCounter("RTWDiagHTSGI40Negotiated",(uint64_t)((usesFirmwareRate()&&core_.rate_config.sgi40)||(r88HT&&r88Rates_.width_mhz==40&&hwRate->sgi20)||(buHT&&buRate_.width_mhz==40&&buRate_.sgi)||(fuHT&&fuRate_.width_mhz==40&&fuRate_.sgi)||(auHT&&auRateConfig_.bandwidth_mhz==40&&auRateConfig_.short_gi)));
    publishDiagnosticCounter("RTWDiagVHTSGI80Negotiated",(uint64_t)((r88VHT&&r88Rates_.width_mhz==80&&hwRate->sgi20)||(auVHT&&auRateConfig_.bandwidth_mhz==80&&auRateConfig_.short_gi)));
    publishDiagnosticCounter("RTWDiagHTChannelWidthMHz",(uint64_t)(r88HT?r88Rates_.width_mhz:r23HT||legacyHT?20:buHT?buRate_.width_mhz:fuHT?fuRate_.width_mhz:duHT?20:auHT?auRateConfig_.bandwidth_mhz:acHT?20:usesFirmwareRate()?(core_.rate_config.bw40?40:20):0));
    publishDiagnosticCounter("RTWDiagHTTXStreams",htNegotiated?(uint64_t)(r23HT||buHT?1:fuHT?((fuRate_.mask&0x0ff00000U)?2:1):duHT?((duMAC_.rates.mask&0x0ff00000U)?2:1):auHT?auRateConfig_.streams:acHT?hwRate->tx_streams:core_.rate_config.tx_streams):0);
    publishDiagnosticCounter("RTWDiagHTRAID",htNegotiated?(uint64_t)(r23HT?r23Rates_.raid:buHT?buRate_.rate_id:fuHT?fuRate_.rate_id:duHT?duMAC_.rates.raid:auHT?auRateConfig_.rate_id:acHT?hwRate->rate_id:core_.rate_config.raid):0);
    publishDiagnosticCounter("RTWDiagHTFWRateSubmitted",txHTPackets_);
    publishDiagnosticCounter("RTWDiagHTTXAMPDURequested",txAMPDUPackets_);
    publishDiagnosticCounter("RTWDiagHTRXBARPackets",rxBARPackets_);
    uint64_t txBA=0,rxBA=0;
    if(associated)for(unsigned tid=0;tid<16;++tid){
        if(node->ni_tx_ba[tid].ba_state==IEEE80211_BA_AGREED)txBA|=1U<<tid;
        if(node->ni_rx_ba[tid].ba_state==IEEE80211_BA_AGREED)rxBA|=1U<<tid;
    }
    publishDiagnosticCounter("RTWDiagHTTXBATIDs",txBA);publishDiagnosticCounter("RTWDiagHTRXBATIDs",rxBA);
    publishDiagnosticCounter("RTWDiagTXRateFeedbackActive",(uint64_t)(r.active&&rateTransportFresh_&&running_&&!stopping_&&
        authorized()&&core_.sc_ic.ic_state==IEEE80211_S_RUN&&node&&IEEE80211_ADDR_EQ(r.bssid,node->ni_bssid)));
    publishDiagnosticCounter("RTWDiagTXRateRequests",r.requests);publishDiagnosticCounter("RTWDiagTXRatePending",r.pendingReports);
    publishDiagnosticCounter("RTWDiagTXRateReports",r.reports);publishDiagnosticCounter("RTWDiagTXRateFailures",r.failures);
    publishDiagnosticCounter("RTWDiagTXRateRetried",r.retried);publishDiagnosticCounter("RTWDiagTXRateInvalid",r.invalid);
    publishDiagnosticCounter("RTWDiagTXRateIgnored",r.ignored);publishDiagnosticCounter("RTWDiagTXRateRepeatedSequence",r.repeatedSequences);
    publishDiagnosticCounter("RTWDiagTXRateChanges",r.changes);publishDiagnosticCounter("RTWDiagTXRateResets",r.resets);
    publishDiagnosticCounter("RTWDiagTXFinalHardwareRate",(uint64_t)r.finalRate);
}
int RTWUSBController::sendFrame(mbuf_t packet,ieee80211_node*node) {
    if(!dfsFrameAllowed(packet,node)){if(packet)mbuf_freem(packet);return EACCES;}
    if(is8723Family())return send8723Frame(packet,node);
    if(is8710BUFamily())return send8710BUFrame(packet,node);
    if(is8192FUFamily())return send8192FUFrame(packet,node);
    if(family_==RTW_WIFI_RTL8192DU)return send8192DUFrame(packet,node);
    if(is88Family())return send88Frame(packet,node);
    if(is8812Family())return send8812Frame(packet,node);
    if(!packet)return EINVAL;
    if(!running_||stopping_||!present_||usbError_!=kIOReturnSuccess||!node){mbuf_freem(packet);return ENETDOWN;}
    if(family_==RTW_WIFI_RTL8814AU&&(!acCore_.phy_initialized||acCore_.io_error)){mbuf_freem(packet);return ENETDOWN;}
    ieee80211_frame header{};size_t length=mbuf_pkthdr_len(packet);
    if(length<sizeof(header)||length>4096||mbuf_copydata(packet,0,sizeof(header),&header)){mbuf_freem(packet);return EINVAL;}
    auto&ic=core_.sc_ic;
    const bool data=(header.i_fc[0]&IEEE80211_FC0_TYPE_MASK)==IEEE80211_FC0_TYPE_DATA;
    const bool multicast=(header.i_addr1[0]&1)!=0;
    const bool qos=data&&(header.i_fc[0]&IEEE80211_FC0_SUBTYPE_QOS);
    if(family_!=RTW_WIFI_RTL8192EU&&family_!=RTW_WIFI_RTL8814AU&&qos&&!usesLegacyHighThroughput()){mbuf_freem(packet);return EINVAL;}
    const size_t headerLength=qos?sizeof(header)+2:sizeof(header);
    uint8_t qosBytes[2]{},llc[8]{};
    if((header.i_fc[1]&IEEE80211_FC1_DIR_MASK)==IEEE80211_FC1_DIR_DSTODS ||
       length<headerLength || (qos&&mbuf_copydata(packet,sizeof(header),2,qosBytes))){mbuf_freem(packet);return EINVAL;}
    const unsigned tid=qos?(qosBytes[0]&IEEE80211_QOS_TID):0;
    if(tid>7){mbuf_freem(packet);return EINVAL;}
    /* Inspect SNAP before CCMP encryption, including protected group rekeys. */
    const bool eapol=data&&length>=headerLength+sizeof(llc)&&
        !mbuf_copydata(packet,headerLength,sizeof(llc),llc)&&
        llc[0]==0xaa&&llc[1]==0xaa&&llc[2]==3&&llc[3]==0&&llc[4]==0&&llc[5]==0&&llc[6]==0x88&&llc[7]==0x8e;
    if(header.i_fc[1]&IEEE80211_FC1_PROTECTED){
        auto*key=ieee80211_get_txkey(&ic,&header,node);
        if(!key||key->k_cipher!=IEEE80211_CIPHER_CCMP){mbuf_freem(packet);return EINVAL;}
        packet=ieee80211_encrypt(&ic,packet,key);
        if(!packet)return ENOBUFS;
        length=mbuf_pkthdr_len(packet);
    }
    unsigned index=RTW_TRANSFER_SLOTS;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    for(unsigned i=RXSlots;i<RTW_TRANSFER_SLOTS;i++)if(!(ledger_.pending&(1U<<i))){index=i;break;}
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(index==RTW_TRANSFER_SLOTS||length>4096){mbuf_freem(packet);return ENOBUFS;}
    const bool firmware=qos&&!multicast&&!eapol&&node==ic.ic_bss&&usesFirmwareRate();
    const bool legacyHT=qos&&!multicast&&!eapol&&node==ic.ic_bss&&usesLegacyHighThroughput();
    const bool legacyFirmware=data&&!multicast&&!eapol&&node==ic.ic_bss&&usesLegacyFirmwareRate()&&(!usesLegacyHighThroughput()||qos);
    const bool gen2=family_==RTW_WIFI_RTL8192EU;
    const bool ac8814=family_==RTW_WIFI_RTL8814AU;
    const bool acFirmware=data&&!multicast&&!eapol&&node==ic.ic_bss&&uses8814FirmwareRate()&&(!acRateConfig_.ht||qos);
    const size_t descriptorLength=(gen2||ac8814)?40U:32U;
    unsigned ac=data?(qos?ieee80211_up_to_ac(&ic,tid):EDCA_AC_BE):EDCA_AC_VO;
    unsigned pipeIndex=ac8814&&multicast?0:core_.ac2idx[ac];
    if(pipeIndex>=endpoints_.num_bulk_out){mbuf_freem(packet);return EINVAL;}
    static const uint8_t values[12]={2,4,11,22,12,18,24,36,48,72,96,108};
    const bool band5g=ac8814&&node->ni_chan&&node->ni_chan!=IEEE80211_CHAN_ANYC&&(node->ni_chan->ic_flags&IEEE80211_CHAN_5GHZ)!=0;
    uint8_t rate=band5g?4:0;uint8_t raid=band5g?7:8;
    if(node->ni_rates.rs_nrates>nitems(node->ni_rates.rs_rates)){mbuf_freem(packet);return EINVAL;}
    if(node->ni_rates.rs_nrates){
        unsigned selected=node->ni_txrate<node->ni_rates.rs_nrates?node->ni_txrate:0;
        if(!data||multicast||eapol){
            selected=0;unsigned lowest=256;bool basic=false;
            for(unsigned r=0;r<node->ni_rates.rs_nrates;r++){
                const unsigned v=node->ni_rates.rs_rates[r]&IEEE80211_RATE_VAL;
                const bool b=(node->ni_rates.rs_rates[r]&IEEE80211_RATE_BASIC)!=0;
                if(band5g&&(v==2||v==4||v==11||v==22))continue;
                if((b&&!basic)||(b==basic&&v<lowest)){selected=r;lowest=v;basic=b;}
            }
        }
        const uint8_t value=node->ni_rates.rs_rates[selected]&IEEE80211_RATE_VAL;
        bool found=false;for(uint8_t hw=0;hw<12;hw++)if(values[hw]==value){rate=hw;found=true;break;}
        if(!found||(band5g&&rate<4)){mbuf_freem(packet);return EINVAL;}
        uint16_t mask=0;for(unsigned r=0;r<node->ni_rates.rs_nrates;r++)for(unsigned hw=0;hw<12;hw++)
            if((node->ni_rates.rs_rates[r]&IEEE80211_RATE_VAL)==values[hw])mask|=(uint16_t)(1U<<hw);
        raid=(mask&0xff0U)?((mask&15U)?6:7):8;
    }
    rtw_92e_tx_options options{};
    options.data=data&&!multicast;options.multicast=multicast;options.raid=firmware?core_.rate_config.raid:raid;
    options.rate=firmware?core_.rate_config.initial_rate:rate;options.firmware_rate=firmware||legacyFirmware;
    /* Gen2 DW5 describes each packet's width and primary subchannel.
     * Legacy/EAPOL/management stay at 20MHz on an HT40 radio as well. */
    if(gen2&&core_.channel_bw40){
        const unsigned sco=ic.ic_bss?ic.ic_bss->ni_htop0&IEEE80211_HTOP0_SCO_MASK:0;
        if(sco!=IEEE80211_HTOP0_SCO_SCA&&sco!=IEEE80211_HTOP0_SCO_SCB){mbuf_freem(packet);return EINVAL;}
        options.channel_bw40=1;
        options.primary_above=(sco==IEEE80211_HTOP0_SCO_SCB);
    }
    if(gen2&&firmware&&qos){
        options.bw40=core_.rate_config.bw40;
        options.short_gi=options.bw40?core_.rate_config.sgi40:core_.rate_config.sgi20;
    }
    if(!gen2)options.raid=raid==6?4:raid==7?5:6;
    if(legacyHT) {
        options.rate=legacyFirmware?core_.rate_config.initial_rate:legacyHostHTRate();
        if(!(core_.rate_config.rate_mask&(1U<<options.rate))){mbuf_freem(packet);return EINVAL;}
        if(options.rate>=12){options.raid=core_.rate_config.raid;options.short_gi=core_.rate_config.sgi20;}
    }
    /* Preserve header TID and its sequence, while honoring ACM queue downgrade. */
    static const uint8_t queues[4]={0,2,5,7};
    const unsigned nativeAC=(tid==1||tid==2)?EDCA_AC_BK:(tid==4||tid==5)?EDCA_AC_VI:tid>=6?EDCA_AC_VO:EDCA_AC_BE;
    options.qsel=options.data?(qos&&ac==nativeAC?(uint8_t)tid:queues[ac]):0x12;
    options.sequence=((uint16_t)header.i_seq[0]|(uint16_t)header.i_seq[1]<<8)>>4;
    options.short_preamble=(ic.ic_flags&IEEE80211_F_SHPREAMBLE)&&options.rate>=1&&options.rate<=3&&!firmware;
    if((firmware||(legacyHT&&options.rate>=12&&authorized()&&options.qsel==tid&&
       !(ic.ic_tid_noack&(1U<<tid))&&!(header.i_fc[0]&IEEE80211_FC0_SUBTYPE_NODATA)&&
       !(header.i_fc[1]&IEEE80211_FC1_MORE_FRAG)&&!(header.i_seq[0]&15U)&&
       node->ni_tx_ba[tid].ba_winsize>=1&&node->ni_tx_ba[tid].ba_winsize<=IEEE80211_BA_MAX_WINSZ))&&qos&&(qosBytes[0]&IEEE80211_QOS_ACK_POLICY_MASK)==IEEE80211_QOS_ACK_POLICY_NORMAL&&
       node->ni_tx_ba[tid].ba_state==IEEE80211_BA_AGREED){
        options.ampdu=1;options.density=(node->ni_ampdu_param&IEEE80211_AMPDU_PARAM_SS)>>2;
        options.max_agg=(uint8_t)MIN(16,node->ni_tx_ba[tid].ba_winsize);
    }
    size_t total=0;
    if(rtw_tx_total_transfer_size_for_descriptor(descriptorLength,length,txMPS_[pipeIndex],&total)!=RTW_PACKETS_OK||total>TXCapacity){mbuf_freem(packet);return EINVAL;}
    auto*t=&transfers_[index];auto*bytes=static_cast<uint8_t*>(t->memory->getBytesNoCopy());
    bzero(bytes,total);
    if(!ac8814&&!(gen2?rtw_92e_make_tx_descriptor_ex(length,&options,bytes):rtw_92c_make_tx_descriptor_ex(length,family_==RTW_WIFI_RTL8188EU,qos,&options,bytes))){mbuf_freem(packet);return EINVAL;}
    unsigned protection=0;
    if(options.data){
        unsigned htprotection=node->ni_htop1&IEEE80211_HTOP1_PROT_MASK;
        /* BA aggregation alone does not mandate RTS/CTS on each MPDU.
         * Honor the RTS threshold, mixed HT protection and 20MHz-only
         * stations when using HT40, as required by the AP operation IE. */
        if(length+4>(unsigned)ic.ic_rtsthreshold||
           ((firmware||legacyHT||(acFirmware&&acRateConfig_.ht))&&(htprotection==1||htprotection==3||
              (htprotection==2&&core_.rate_config.bw40))))protection=1;
        else if(ic.ic_flags&IEEE80211_F_USEPROT)protection=ic.ic_protmode==IEEE80211_PROT_CTSONLY?2:ic.ic_protmode==IEEE80211_PROT_RTSCTS?1:0;
    }
    bool requestReport=options.data&&!eapol&&!legacyFirmware&&authorized()&&ic.ic_state==IEEE80211_S_RUN&&
        node==ic.ic_bss&&rateControl_.active&&rateTransportFresh_&&
        IEEE80211_ADDR_EQ(rateControl_.bssid,node->ni_bssid)&&
        (!firmware||((++rateControl_.htSampleCounter&31U)==0));
    bool descriptorOK=false;
    if(ac8814){
        rtw_8814au_tx_options acOptions{};
        acOptions.data=data;acOptions.multicast=multicast;acOptions.eapol=eapol;
        acOptions.qsel=data?options.qsel:0x12;acOptions.rate=acFirmware?acRateConfig_.initial_rate:rate;
        acOptions.firmware_rate=acFirmware;acOptions.sequence=options.sequence;
        acOptions.short_gi=acFirmware&&acRateConfig_.ht&&acRateConfig_.sgi20;
        acOptions.short_preamble=(ic.ic_flags&IEEE80211_F_SHPREAMBLE)&&acOptions.rate>=1&&acOptions.rate<=3;
        /* Use RTS/CTS when protection is requested; this codec has no
         * verified standalone CTS-to-self encoding. */
        acOptions.protection=protection?1:0;
        acOptions.qos=qos;
        acOptions.ack_expected=qos&&(qosBytes[0]&IEEE80211_QOS_ACK_POLICY_MASK)==IEEE80211_QOS_ACK_POLICY_NORMAL&&
            !(ic.ic_tid_noack&(1U<<tid));
        acOptions.fragment=(header.i_fc[1]&IEEE80211_FC1_MORE_FRAG)||(header.i_seq[0]&0x0fU);
        const auto&ba=node->ni_tx_ba[tid];
        if(acFirmware&&acRateConfig_.ht&&authorized()&&qos&&!(header.i_fc[0]&IEEE80211_FC0_SUBTYPE_NODATA)&&
           acOptions.ack_expected&&!acOptions.fragment&&
           (node->ni_flags&IEEE80211_NODE_HT)&&acOptions.qsel==tid&&
           ba.ba_state==IEEE80211_BA_AGREED&&ba.ba_winsize>=2&&ba.ba_winsize<=IEEE80211_BA_MAX_WINSZ){
            acOptions.ampdu=1;acOptions.density=(node->ni_ampdu_param&IEEE80211_AMPDU_PARAM_SS)>>2;
            /* Linux get_tx_ampdu_factor: DW3 counts pairs of MPDUs.
             * Bound both the peer HT factor and the live receive window. */
            const unsigned peerPairs=(4U<<(node->ni_ampdu_param&IEEE80211_AMPDU_PARAM_LE))-1U;
            acOptions.max_agg=(uint8_t)MIN(16U,MIN(peerPairs,(unsigned)ba.ba_winsize/2U));
        }
        options.ampdu=acOptions.ampdu;
        descriptorOK=rtw_8814au_make_tx_descriptor(length,&acOptions,acFirmware?&acRateConfig_:nullptr,bytes);
        requestReport=false;
        /* Thermal tracking retains the effective rate from accepted C2H. */
    }else if(gen2)descriptorOK=rtw_92e_tx_protection(protection,bytes)&&rtw_92e_tx_report_request(requestReport?1:0,bytes);
    else descriptorOK=rtw_92c_tx_protection(protection,bytes)&&rtw_92c_tx_report_request(family_==RTW_WIFI_RTL8188EU,requestReport?1:0,bytes);
    if(!descriptorOK||mbuf_copydata(packet,0,length,bytes+descriptorLength)){mbuf_freem(packet);return EINVAL;}
    mbuf_freem(packet);
    int error=submit(index,txPipes_[pipeIndex],(uint32_t)total);
    if(!error){
        if(requestReport){++rateControl_.requests;++rateControl_.pendingReports;rateControl_.requestedSinceReset=true;}
        if(firmware||(legacyHT&&options.rate>=12)||(acFirmware&&acRateConfig_.ht))++txHTPackets_;
        if(options.ampdu){++txAMPDUPackets_;auto&ba=node->ni_tx_ba[tid];if(ba.ba_timeout_val)timeout_add_usec(&ba.ba_to,ba.ba_timeout_val);}
        ieee80211_release_node(&ic,node);
    }
    return error;
}
void RTWUSBController::updateFirmwareRSSI(const rtw_rx_packet&p,int dbm,unsigned percent) {
    const auto*n=core_.sc_ic.ic_bss;
    /* Per-frame RSSI still belongs to its RX node during scanning. Firmware
     * rate feedback and the association average must only use the linked AP.
     * RUN may precede WPA authorization, so do not gate this on port_valid. */
    if(!p.phy_status_present||!rtw_signal_valid_dbm(dbm)||
       core_.sc_ic.ic_state!=IEEE80211_S_RUN||!n||
       !rtw_signal_from_ap(p.mpdu,p.mpdu_length,n->ni_bssid))return;
    if(family_==RTW_WIFI_RTL8814AU){
        if(percent>100U)return;
        acRSSI_=(uint8_t)percent;
    }
    if(family_==RTW_WIFI_RTL8192CU||family_==RTW_WIFI_RTL8188EU||family_==RTW_WIFI_RTL8192EU)
        rtwn_update_avgrssi(&core_,p.rate_index,(int8_t)dbm);
    else{
        const auto value=rtw_signal_node_value(dbm);
        core_.avg_pwdb=core_.avg_pwdb<0?value:(core_.avg_pwdb*19+value)/20;
    }
}
void RTWUSBController::receive(const uint8_t*bytes,size_t length) {
    if(!attached_||!running_||!netif_||!stats_||!core_.sc_ic.ic_if.iface)return;
    ++rxDiag_.aggregates;rxDiag_.bytes+=length;
    rxDiag_.lastReadBytes=length;
    if(length>rxDiag_.maxReadBytes)rxDiag_.maxReadBytes=length;
    /* Decode everything structurally before any delivery. If a later RX
     * descriptor is corrupt, salvage ONLY an already validated prefix;
     * no malformed bytes ever reach net80211. All chipset codecs share this
     * preflight, including 8814AU's FCS length and C2H validation. */
    auto decode=[](rtw_rx_iterator*it,void*context)->rtw_packet_error{
        auto*self=static_cast<RTWUSBController*>(context);
        rtw_8192eu_rx_frame checked{};uint8_t type=0;
        return self->decodeUSBFrame(it,&checked,&type);
    };
    rtw_rx_preflight_result prefix{};
    rtw_packet_error result=rtw_rx_preflight_transfer(bytes,length,decode,this,&prefix);
    if(result!=RTW_PACKETS_DONE){
        ++rxDiag_.aggregateErrors;
        rxDiag_.lastAggregateErrorReadBytes=length;
        switch(result){
        case RTW_PACKETS_TRUNCATED: ++rxDiag_.aggregateTruncated;break;
        case RTW_PACKETS_MALFORMED: ++rxDiag_.aggregateMalformed;break;
        case RTW_PACKETS_TOO_MANY: ++rxDiag_.aggregateTooMany;break;
        default: ++rxDiag_.aggregateBadArgument;break;
        }
        rxDiag_.lastAggregateErrorOffset=prefix.error_offset;
        rxDiag_.lastAggregateErrorFrames=prefix.error_frames;
        rxErrors_++;stats_->inputErrors++;
        if(!prefix.valid_frames)return; /* invalid first frame: reject all */
        ++rxDiag_.partialAggregates;
        rxDiag_.partialPrefixFrames+=prefix.valid_frames;
        rxDiag_.partialPrefixBytes+=prefix.valid_bytes;
    }
    /* A second parse is deliberately bounded to the validated prefix.
     * Never decode (or deliver) any part of the invalid USB suffix. */
    rtw_rx_iterator iterator;rtw_rx_iterator_init(&iterator,bytes,prefix.valid_bytes);
    rtw_8192eu_rx_frame frame{};uint8_t reportType=0;
    mbuf_list list=MBUF_LIST_INITIALIZER();
    while(decodeUSBFrame(&iterator,&frame,&reportType)==RTW_PACKETS_OK){
        const auto&p=frame.payload;
        if(reportType){++rxDiag_.c2h;if(reportType==7)handle8723C2H(p.mpdu,p.mpdu_length);else if(reportType==6)handle88C2H(p.mpdu,p.mpdu_length);else if(reportType==5){if(is8192FUFamily())handle8192FUC2H(p.mpdu,p.mpdu_length);else if(is8710BUFamily())handle8710BUC2H(p.mpdu,p.mpdu_length);else handle8812C2H(p.mpdu,p.mpdu_length);}else if(reportType==4)handle8814C2H(p.mpdu,p.mpdu_length);else if(reportType==1)handleTxReport(p.mpdu,p.mpdu_length);continue;}
        uint64_t*drop=nullptr;
        /* RTL radio ABI: while the AWDL hook is attached, every received
         * 802.11 frame whose A3 is the AWDL BSSID goes to the hook as raw
         * bytes (header included, FCS stripped, rssi + current channel) and
         * is dropped here afterwards. NOTE hardware coverage: whether the
         * chip's RX filter lets foreign-BSSID frames reach USB at all is
         * unverified on 8821C silicon; the software tap below is complete
         * either way, the awdlsim test port does not depend on it. */
        if(radioAwdlHook_&&p.mpdu&&p.mpdu_length>=24&&(p.mpdu[0]&IEEE80211_FC0_TYPE_MASK)!=IEEE80211_FC0_TYPE_CTL){
            static const uint8_t awdlBSSID[6]={0x00,0x25,0x00,0xff,0x94,0x73};
            if(!memcmp(p.mpdu+16,awdlBSSID,6)){
                rtw88_rx_phy_sample sample{};int8_t rssi=0;
                if(rtw88_rx_parse_phy(&r88RX_,&p,&sample))rssi=(int8_t)sample.signal_dbm;
                /* The channel the frame was heard on: during an AWDL slot the PHY
                 * sits on radioOffchChannel_ while r88Channel_ stays on the BSS.
                 * Reporting the BSS made IO80211 see every peer "on 2.4GHz
                 * only ... outside bubble" (isPeerRoutable: Not Routable), so
                 * AirDrop never routed to it (efi-awdl 2026-11-25). */
                const uint8_t rxChannel=radioOffchState_&&radioOffchChannel_?radioOffchChannel_:r88Channel_;
                radioAwdlHook_(radioAwdlHookCtx_,p.mpdu,p.mpdu_length,rssi,rxChannel);
                continue;
            }
        }
        const bool authorizedHT=authorized()&&(usesFirmwareRate()||usesLegacyHighThroughput()||(uses8814FirmwareRate()&&acRateConfig_.ht)||uses88HighThroughput()||uses8812HighThroughput()||uses8192FUHighThroughput()||uses8710BUHighThroughput()||(uses8723FirmwareRate()&&(r23Rates_.mask&0xff000U))||(uses8192DUFirmwareRate()&&duMAC_.rates.ht));
        const uint8_t*peer=core_.sc_ic.ic_bss?core_.sc_ic.ic_bss->ni_bssid:nullptr;
        rtw_rx_admission_reason admissionReason=RTW_RX_REJECT_RATE;
        if(((family_==RTW_WIFI_RTL8192CU||family_==RTW_WIFI_RTL8188EU)&&!acceptsLegacyReceiveRate(p))||(is8723Family()&&(p.rate_index>=20||(p.rate_index>=12&&(!uses8723FirmwareRate()||!(r23Rates_.mask&0xff000U)||p.bandwidth_code))))||(is8710BUFamily()&&!accepts8710BUReceiveRate(p))||(is8192FUFamily()&&!accepts8192FUReceiveRate(p))||(family_==RTW_WIFI_RTL8192DU&&p.rate_index>=12U+8U*core_.nrxchains)||(is8812Family()&&!accepts8812ReceiveRate(p))||(is88Family()&&!accepts88ReceiveRate(p))||(family_==RTW_WIFI_RTL8814AU&&p.rate_index>27)||
           (family_!=RTW_WIFI_RTL8192CU&&family_!=RTW_WIFI_RTL8188EU&&family_!=RTW_WIFI_RTL8192EU&&family_!=RTW_WIFI_RTL8814AU&&!is88Family()&&!is8812Family()&&family_!=RTW_WIFI_RTL8192DU&&family_!=RTW_WIFI_RTL8192FU&&family_!=RTW_WIFI_RTL8710BU&&family_!=RTW_WIFI_RTL8723BU&&p.rate_index>=12))drop=&rxDiag_.invalidFrameDrops;
        else if(p.crc_error)drop=&rxDiag_.crcDrops;
        else if(p.icv_error)drop=&rxDiag_.icvDrops;
        else if((admissionReason=rtw_92e_rx_frame_reason(p.mpdu,p.mpdu_length,authorizedHT,
                core_.sc_ic.ic_myaddr,peer))!=RTW_RX_ADMIT)drop=&rxDiag_.invalidFrameDrops;
        else if(frame.security_code&&!frame.sw_decrypt_required)drop=&rxDiag_.hardwareDecryptDrops;
        if(drop){
            /* Hardware/FW TX feedback is independent of this received copy.
             * Consume only an ordinary validated BA; never apply its bitmap,
             * change BA state, or reinterpret a USB completion as an ACK. */
            if(drop==&rxDiag_.invalidFrameDrops&&admissionReason==RTW_RX_REJECT_CONTROL&&
               !frame.security_code&&rtw_92e_rx_ba_consumable(p.mpdu,p.mpdu_length,
                   authorizedHT,core_.sc_ic.ic_myaddr,peer)){
                ++rxDiag_.blockAckFiltered;continue;
            }
            if(drop==&rxDiag_.invalidFrameDrops){
                ++rxDiag_.rejectedReasons[admissionReason];
                if(admissionReason==RTW_RX_REJECT_CONTROL&&p.mpdu&&p.mpdu_length)
                    ++rxDiag_.rejectedControlSubtypes[p.mpdu[0]>>4];
                rxDiag_.rejectLastReason=admissionReason;
                rxDiag_.rejectLastLength=p.mpdu_length;rxDiag_.rejectLastMS=nowMS();
                rxDiag_.rejectLastType=p.mpdu&&p.mpdu_length?((p.mpdu[0]>>2)&3U):255U;
                rxDiag_.rejectLastSubtype=p.mpdu&&p.mpdu_length?(p.mpdu[0]>>4):255U;
                rxDiag_.rejectLastFlags=p.mpdu&&p.mpdu_length>=2U?p.mpdu[1]:0U;
                rxDiag_.rejectLastVersion=p.mpdu&&p.mpdu_length?(p.mpdu[0]&3U):255U;
                rxDiag_.rejectLastSecurity=frame.security_code;
                rxDiag_.rejectLastSoftwareDecrypt=frame.sw_decrypt_required;
                rxDiag_.rejectLastPHY=p.phy_status_present;
                rxDiag_.rejectLastPHYBytes=p.phy_info_length;
                rxDiag_.rejectLastReceiverMatch=p.mpdu&&p.mpdu_length>=10U&&
                    !memcmp(p.mpdu+4,core_.sc_ic.ic_myaddr,6);
                rxDiag_.rejectLastTransmitterMatch=p.mpdu&&p.mpdu_length>=16U&&core_.sc_ic.ic_bss&&
                    !memcmp(p.mpdu+10,core_.sc_ic.ic_bss->ni_bssid,6);
                rxDiag_.rejectLastState=core_.sc_ic.ic_state;
                rxDiag_.rejectLastAuthorized=authorized();
                rxDiag_.rejectLastReadBytes=length;rxDiag_.rejectLastRate=p.rate_index;
                rxDiag_.rejectLastBAControl=65535;rxDiag_.rejectLastBAFragment=255;
                if(p.mpdu&&p.mpdu_length>=18U&&(p.mpdu[0]&0xfcU)==0x94U){
                    rxDiag_.rejectLastBAControl=(unsigned)p.mpdu[16]|((unsigned)p.mpdu[17]<<8U);
                    if(p.mpdu_length>=20U)rxDiag_.rejectLastBAFragment=p.mpdu[18]&15U;
                }
            }
            ++*drop;rxErrors_++;stats_->inputErrors++;continue;
        }
        if((p.mpdu[0]&IEEE80211_FC0_TYPE_MASK)==IEEE80211_FC0_TYPE_CTL)++rxBARPackets_;
        observeReceivedRate(p);
        if(p.mpdu[1]&IEEE80211_FC1_PROTECTED)++rxDiag_.protectedMPDUs;
        /* Beacons establish RF freshness throughout WPA2 key exchange, before
         * net80211 opens the controlled port for Ethernet traffic. */
        if(present_&&joinRequested_&&core_.sc_ic.ic_state==IEEE80211_S_RUN&&
           associatedBeacon(p.mpdu,p.mpdu_length))lastBeaconMs_=nowMS();
        ieee80211_rxinfo info{};
        int measuredRSSI=0;
        unsigned firmwarePercent=0;
        unsigned scanPhysicalChannel=0;
        if(family_==RTW_WIFI_RTL8814AU&&p.phy_status_present){
            rtw_8814au_rx_frame acFrame{};acFrame.packet=p;rtw_8814au_phy_status phy{};
            if(rtw_8814au_parse_phy(&acFrame,acCore_.board.antenna_rx,&phy)){
                measuredRSSI=phy.signal_dbm;
                scanPhysicalChannel=phy.channel;
                firmwarePercent=phy.rssi;
            }
        }else if(is8723Family()){
            measuredRSSI=sample8723RSSI(p);
        }else if(is8710BUFamily()){
            measuredRSSI=sample8710BURSSI(p);
        }else if(is8192FUFamily()){
            measuredRSSI=sample8192FURSSI(p);
        }else if(family_==RTW_WIFI_RTL8192DU){
            measuredRSSI=sample8192DURSSI(p);
        }else if(is88Family()){
            measuredRSSI=sample88RSSI(p);
        }else if(is8812Family()){
            measuredRSSI=sample8812RSSI(p);
        }else if(p.phy_status_present&&p.phy_info_length>=sizeof(r92c_rx_phystat)){
            measuredRSSI=rtwn_get_rssi(&core_,p.rate_index,const_cast<uint8_t*>(p.phy_info));
        }
        if(rtw_signal_valid_dbm(measuredRSSI)){
            info.rxi_rssi=rtw_signal_node_value(measuredRSSI);
            updateFirmwareRSSI(p,measuredRSSI,firmwarePercent);
        }
        info.rxi_tstamp=p.timestamp;
        auto*channel=core_.sc_ic.ic_bss?core_.sc_ic.ic_bss->ni_chan:nullptr;
        if(channel&&channel!=IEEE80211_CHAN_ANYC)info.rxi_chan=(uint8_t)ieee80211_chan2ieee(&core_.sc_ic,channel);
        /* Only decoded AU PHY status supplies physical-channel evidence. A
         * missing/zero PHY channel stays unknown; never copy the software
         * scan channel into it. Mismatches do not affect packet delivery. */
        observeDFSFrame(p.mpdu,p.mpdu_length,scanPhysicalChannel);
        rtw::scanDiagnosticsFrame(scanDiag_,core_.sc_ic.ic_state==IEEE80211_S_SCAN,
            p.mpdu,p.mpdu_length,info.rxi_chan,scanPhysicalChannel);
        /* DFS quiet/power admission above must run even under mbuf pressure. */
        mbuf_t packet=nullptr;unsigned chunks=1;
        if(mbuf_allocpacket(MBUF_DONTWAIT,p.mpdu_length,&chunks,&packet)||!packet){++rxDiag_.allocationDrops;rxErrors_++;stats_->inputErrors++;continue;}
        if(mbuf_copyback(packet,0,p.mpdu_length,p.mpdu,MBUF_DONTWAIT)){++rxDiag_.copyDrops;mbuf_freem(packet);rxErrors_++;continue;}
        auto*header=static_cast<ieee80211_frame*>(mbuf_data(packet));
        auto*node=ieee80211_find_rxnode(&core_.sc_ic,header);
        if(!node){++rxDiag_.noNodeDrops;mbuf_freem(packet);rxErrors_++;continue;}
        /* Missing PHY is not a zero-strength measurement. Preserve only this
         * transmitter's node value; never borrow RSSI from a different AP. */
        if(!info.rxi_rssi&&rtw_signal_from_ap(p.mpdu,p.mpdu_length,node->ni_bssid))
            info.rxi_rssi=node->ni_rssi;
        if(core_.sc_ic.ic_state==IEEE80211_S_RUN&&core_.sc_ic.ic_bss)
            rtw_signal_observe(&signal_,core_.sc_ic.ic_bss->ni_bssid,info.rxi_chan,
                p.mpdu,p.mpdu_length,p.phy_status_present,measuredRSSI,nowMS());
        ieee80211_inputm(&core_.sc_ic.ic_if,packet,node,&info,&list);
        ieee80211_release_node(&core_.sc_ic,node);rxPackets_++;
    }
    rxDiag_.ethernetQueued+=list.ml_len;
    if(if_input(&core_.sc_ic.ic_if,&list)!=kIOReturnSuccess)++rxDiag_.handoffErrors;
}
void RTWUSBController::scanAction(OSObject*o,IOTimerEventSource*) {auto*s=static_cast<RTWUSBController*>(o);if(s->running_&&!s->stopping_){if(s->rxRecovery_.pending||s->dfsTXBlocked()){s->scanTimer_->setTimeoutMS(100);return;}rtwn_next_scan(&s->core_);if(rtwn_io_error(&s->core_))s->quiesce(false);}}
void RTWUSBController::calibAction(OSObject*o,IOTimerEventSource*) {
    auto*s=static_cast<RTWUSBController*>(o);
    if(s->dfsTXBlocked())return;
    if(!s->running_||s->stopping_)return;
    if(s->rxRecovery_.pending){s->calibTimer_->setTimeoutMS(100);return;}
    if(s->is8723Family()){
        int e=s->tick8723();
        if(e){s->core_.core_error=e;s->quiesce(false);}
        else if(s->core_.sc_ic.ic_state==IEEE80211_S_RUN)s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->is8710BUFamily()){
        int e=s->tick8710BU();
        if(e){s->core_.core_error=e;s->quiesce(false);}
        else if(s->core_.sc_ic.ic_state==IEEE80211_S_RUN)s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->is8192FUFamily()){
        int e=s->tick8192FU();
        if(e){s->core_.core_error=e;s->quiesce(false);}
        else if(s->core_.sc_ic.ic_state==IEEE80211_S_RUN)s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->family_==RTW_WIFI_RTL8192DU){
        int e=s->tick8192DU();
        if(e){s->core_.core_error=e;s->quiesce(false);}
        else if(s->core_.sc_ic.ic_state==IEEE80211_S_RUN)s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->is88Family()){
        int e=s->tick88();
        if(e){s->core_.core_error=e;s->quiesce(false);}else s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->is8812Family()){
        int e=s->tick8812();
        if(e){s->core_.core_error=e;s->quiesce(false);}else s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    if(s->family_==RTW_WIFI_RTL8814AU){
        int e=s->tick8814();
        if(e){s->record8814Failure(AUThermal,e);s->core_.core_error=e;s->quiesce(false);}else s->calibTimer_->setTimeoutMS(2000);
        return;
    }
    auto&d=s->calibDiag_;
    d.calls++;
    d.lastStartMS=nowMS();
    d.lastH2CPolls=d.lastH2CReadMS=0;
    d.thermalBefore=(uint32_t)s->core_.thcal_lctemp;
    d.thermalState=(uint32_t)s->core_.thcal_state;
    d.active=true;
    rtwn_calib(&s->core_);
    s->chooseRateControl();
    d.active=false;
    d.lastMS=nowMS()-d.lastStartMS;
    if(d.lastMS>d.maxMS)d.maxMS=d.lastMS;
    if(d.lastH2CPolls>d.maxH2CPolls)d.maxH2CPolls=d.lastH2CPolls;
    if(d.lastH2CReadMS>d.maxH2CReadMS)d.maxH2CReadMS=d.lastH2CReadMS;
    d.thermalAfter=(uint32_t)s->core_.thcal_lctemp;
    if(d.thermalBefore!=d.thermalAfter){
        d.thermalChanges++;
        /* A zero baseline is only initialized. A changed nonzero baseline
         * is recorded after rtwn_temp_calib runs both IQ and LC. */
        if(d.thermalBefore)d.thermalIQs++;
    }
    d.generation++;
    if(rtwn_io_error(&s->core_))s->quiesce(false);
}
uint64_t RTWUSBController::nowMS() {
    uint64_t absolute=0,nanoseconds=0;clock_get_uptime(&absolute);
    absolutetime_to_nanoseconds(absolute,&nanoseconds);return nanoseconds/1000000;
}
void RTWUSBController::publishCalibrationDiagnostics() {
    auto publish=[this](const char*name,uint64_t value){publishDiagnosticCounter(name,value);};
    const auto&d=calibDiag_;
    publish("RTWDiagCalibCalls",d.calls);
    publish("RTWDiagCalibGeneration",d.generation);
    publish("RTWDiagCalibLastStartMS",d.lastStartMS);
    publish("RTWDiagCalibLastMS",d.lastMS);
    publish("RTWDiagCalibMaxMS",d.maxMS);
    publish("RTWDiagCalibThermalChanges",d.thermalChanges);
    publish("RTWDiagCalibThermalIQs",d.thermalIQs);
    publish("RTWDiagCalibLastH2CPolls",d.lastH2CPolls);
    publish("RTWDiagCalibMaxH2CPolls",d.maxH2CPolls);
    publish("RTWDiagCalibTotalH2CPolls",d.totalH2CPolls);
    publish("RTWDiagCalibLastH2CReadMS",d.lastH2CReadMS);
    publish("RTWDiagCalibMaxH2CReadMS",d.maxH2CReadMS);
    publish("RTWDiagCalibThermalBefore",d.thermalBefore);
    publish("RTWDiagCalibThermalAfter",d.thermalAfter);
    publish("RTWDiagCalibThermalState",d.thermalState);
}
#include "RTWDFSRegulatory.inc"
#include "RTWDFSStation.inc"
bool RTWUSBController::associatedBeacon(const uint8_t *bytes,size_t length) const {
    if(length<36||!core_.sc_ic.ic_bss)return false;
    const auto*header=reinterpret_cast<const ieee80211_frame*>(bytes);
    if(header->i_fc[0]!=(IEEE80211_FC0_TYPE_MGT|IEEE80211_FC0_SUBTYPE_BEACON)||
       (header->i_fc[1]&(IEEE80211_FC1_DIR_MASK|IEEE80211_FC1_PROTECTED))||
       memcmp(header->i_addr2,core_.sc_ic.ic_bss->ni_bssid,6)||
       memcmp(header->i_addr3,core_.sc_ic.ic_bss->ni_bssid,6))return false;
    for(unsigned i=0;i<6;i++)if(header->i_addr1[i]!=0xff)return false;
    unsigned interval=(unsigned)bytes[32]|((unsigned)bytes[33]<<8);
    if(!interval||!(bytes[34]&IEEE80211_CAPINFO_ESS))return false;
    size_t offset=36;bool ssid=false;
    while(offset<length){
        if(length-offset<2)return false;
        unsigned id=bytes[offset],size=bytes[offset+1];offset+=2;
        if(size>length-offset)return false;
        if(id==IEEE80211_ELEMID_SSID){
            if(size>32||(size&&(size!=(unsigned)core_.sc_ic.ic_des_esslen||memcmp(bytes+offset,core_.sc_ic.ic_des_essid,size))))return false;
            ssid=true;
        }
        offset+=size;
    }
    return ssid;
}
void RTWUSBController::watchdogAction(OSObject*o,IOTimerEventSource*) {
    auto*s=static_cast<RTWUSBController*>(o);
    if(!s->running_||s->stopping_)return;
    s->advanceDFSRecovery();
    if(!s->running_||s->stopping_||s->dfsTXBlocked())return;
    s->advanceRXRecovery();
    if(!s->running_||s->stopping_)return;
    if(s->rxRecovery_.pending){s->watchdogTimer_->setTimeoutMS(100);return;}
    s->advanceWpaRecovery();
    auto&ic=s->core_.sc_ic;
    if(s->authorized()&&rtw_92e_beacon_expired(nowMS(),s->lastBeaconMs_,ic.ic_bss->ni_intval)){
        ic.ic_bss->ni_port_valid=0;
        if(auto*queue=s->getOutputQueue()){queue->stop();queue->flush();}
        ieee80211_set_link_state(&ic,LINK_STATE_DOWN);
        (void)stateTransition(&ic,IEEE80211_S_SCAN,-1);
    }
    ic.ic_if.if_watchdog(&ic.ic_if);
    if(rtwn_io_error(&s->core_))s->quiesce(false);else s->watchdogTimer_->setTimeoutMS(1000);
}
void RTWUSBController::resetWpaRecovery() { wpaRecovery_=WPARecovery{}; }
void RTWUSBController::cancelWpaRecovery() {
    auto&r=wpaRecovery_;
    r.active=false;r.remainingMS=0;r.lastMS=0;
    if(r.state!=WPARecoveryFailed)r.state=WPARecoveryIdle;
}
void RTWUSBController::wpaStateChanged(ieee80211_state previous) {
    auto&r=wpaRecovery_;const auto&ic=core_.sc_ic;
    if(!joinRequested_||!ic.ic_des_esslen||
       (ic.ic_flags&(IEEE80211_F_RSNON|IEEE80211_F_PSK))!=(IEEE80211_F_RSNON|IEEE80211_F_PSK)){
        cancelWpaRecovery();return;
    }
    if(ic.ic_state!=IEEE80211_S_RUN||previous==IEEE80211_S_RUN||authorized()||r.state==WPARecoveryFailed)return;
    /* The imported association path suggests a 5 s RSN management timer but
     * leaves it disabled. Allow three times that interval for a complete
     * WPA2 exchange, independently of beacons and status polling. */
    if(!r.active){r.retries=0;r.error=0;}
    else if(r.state!=WPARecoverySearching)return;
    r.active=true;r.state=WPARecoveryHandshake;r.remainingMS=15000;r.lastMS=nowMS();
}
void RTWUSBController::advanceWpaRecovery() {
    auto&r=wpaRecovery_;auto&ic=core_.sc_ic;
    if(!attached_||!running_||!radioReady_||!enabled_||stopping_||!present_||sleeping_||
       usbError_!=kIOReturnSuccess||core_.core_error||!joinRequested_||!ic.ic_des_esslen||
       (ic.ic_flags&(IEEE80211_F_RSNON|IEEE80211_F_PSK))!=(IEEE80211_F_RSNON|IEEE80211_F_PSK)){
        cancelWpaRecovery();return;
    }
    if(authorized()){
        cancelWpaRecovery();r.state=WPARecoveryAuthorized;return;
    }
    if(!r.active)return;
    const uint64_t now=nowMS(),elapsed=now-r.lastMS;r.lastMS=now;
    /* Uptime is monotonic. Modular subtraction tolerates wrap; a backwards
     * sample rebases the clock without expiring or replenishing the budget. */
    if(elapsed>(~uint64_t(0)>>1))return;
    if(elapsed<r.remainingMS){r.remainingMS-=elapsed;return;}
    r.timeouts++;r.lastSupplicantState=ic.ic_bss?ic.ic_bss->ni_rsn_supp_state:0;
    if(ic.ic_bss)ic.ic_bss->ni_port_valid=0;
    if(auto*queue=getOutputQueue()){queue->stop();queue->flush();}
    ifq_flush(&ic.ic_if.if_snd);
    ieee80211_set_link_state(&ic,LINK_STATE_DOWN);
    /* Only the serialized watchdog runs this teardown. INIT clears host
     * keys and management queues; it neither stops USB nor reloads firmware. */
    core_.sc_tx_timer=0;
    (void)stateTransition(&ic,IEEE80211_S_INIT,-1);
    if(r.retries==3){
        r.active=false;r.state=WPARecoveryFailed;r.error=ETIMEDOUT;r.remainingMS=0;
        if(scanTimer_)scanTimer_->cancelTimeout();
        if(calibTimer_)calibTimer_->cancelTimeout();
        return;
    }
    r.retries++;r.state=WPARecoverySearching;r.remainingMS=15000;r.lastMS=now;
    /* Scan/auth/assoc also has a finite budget if the AP disappears. A new
     * RUN gets one handshake window; repeated RUN notifications do not. */
    (void)stateTransition(&ic,IEEE80211_S_SCAN,-1);
}
void RTWUSBController::publishWpaRecoveryDiagnostics() {
    auto publish=[this](const char*name,uint64_t value){publishDiagnosticCounter(name,value);};
    const auto&r=wpaRecovery_;
    publish("RTWDiagWPARecoveryState",r.state);
    publish("RTWDiagWPARecoveryActive",r.active?1:0);
    publish("RTWDiagWPARecoveryRetries",r.retries);
    publish("RTWDiagWPARecoveryTimeouts",r.timeouts);
    publish("RTWDiagWPARecoveryError",r.error);
    publish("RTWDiagWPARecoveryRemainingMS",r.remainingMS);
    publish("RTWDiagWPARecoveryLastSupplicantState",r.lastSupplicantState);
}
void RTWUSBController::eraseProfile() {
    resetDFSStation();
    resetWpaRecovery();
    joinRequested_=false;browseScanComplete_=false;auto&ic=core_.sc_ic;
    explicit_bzero(ic.ic_psk,sizeof(ic.ic_psk));explicit_bzero(ic.ic_des_essid,sizeof(ic.ic_des_essid));ic.ic_des_esslen=0;
    ic.ic_flags&=~(IEEE80211_F_PSK|IEEE80211_F_RSNON|IEEE80211_F_AUTO_JOIN);
}
void RTWUSBController::quiesce(bool erase) {
    if(stopping_)return;
    stopping_=true;radioReady_=false;enabled_=false;lastBeaconMs_=0;
    rtw_signal_reset(&signal_);
    cancelWpaRecovery();
    resetRateControl();
    if(auto*queue=getOutputQueue()){queue->stop();queue->flush();}
    super::setLinkStatus(kIONetworkLinkValid);
    if(attached_){core_.sc_ic.ic_if.if_flags&=~IFF_UP;if(is8723Family())stop8723();else if(is8710BUFamily())stop8710BU();else if(is8192FUFamily())stop8192FU();else if(family_==RTW_WIFI_RTL8192DU)stop8192DU();else if(is88Family())stop88();else if(is8812Family())stop8812();else if(family_==RTW_WIFI_RTL8814AU)stop8814();else rtwn_stop(&core_.sc_ic.ic_if);ifq_flush(&core_.sc_ic.ic_if.if_snd);}
    else if(completionLock_)abortTransfers();
    if(scanDiag_.state==rtw::ScanDiagnosticState::Active){
        rtw::scanDiagnosticsTransition(scanDiag_,true,rtw::ScanDiagnosticTransition::Init,0,0);
        publishScanDiagnostics();
    }
    resetDFSStation(true);
    if(erase)eraseProfile();
    stopping_=false;
}
IOReturn RTWUSBController::enableStation() {
    if(!attached_||!present_||sleeping_||usbError_!=kIOReturnSuccess||core_.core_error||!netif_||!stats_)return kIOReturnNotReady;
    if(enabled_&&running_)return kIOReturnSuccess;
    core_.sc_ic.ic_if.if_flags|=IFF_UP;
    int result=is8723Family()?start8723():is8710BUFamily()?start8710BU():is8192FUFamily()?start8192FU():family_==RTW_WIFI_RTL8192DU?start8192DU():is88Family()?start88():is8812Family()?start8812():family_==RTW_WIFI_RTL8814AU?start8814():rtwn_init(&core_.sc_ic.ic_if);
    if(result){
        if(isLegacyRecoveryFamily()){failFamilyStart(result);if(result!=EAGAIN&&result!=EBUSY)core_.core_error=result;}
        quiesce(false);return fromErrno(result);
    }
    if(isLegacyRecoveryFamily())finishFamilyStart();
    enabled_=radioReady_=true;
    /* Sequence completion is not a claim that the physical radio has been
     * validated; the stable register-result chain mask remains observable. */
    setProperty("IQCalibrationMask",(unsigned long long)core_.iq_calibration_mask,8);
    return kIOReturnSuccess;
}
uint32_t RTWUSBController::supported5GHzFlags() const {
    if(!attached_)return 0;
    return rtw_station_band_flags([this](uint8_t channel){
        return (core_.sc_ic.ic_channels[channel].ic_flags&(channel<=14?IEEE80211_CHAN_2GHZ:IEEE80211_CHAN_5GHZ))!=0;
    });
}
void RTWUSBController::status(RTWControlStatus*out) {
    bzero(out,sizeof(*out));out->version=RTW_CONTROL_VERSION;
    out->flags|=RTW_CONTROL_SIGNAL_TRACKED;
    out->flags|=supported5GHzFlags();
    if(present_)out->flags|=RTW_CONTROL_DEVICE;
    if(radioReady_)out->flags|=RTW_CONTROL_RADIO;
    if(running_)out->flags|=RTW_CONTROL_RUNNING;
    if(userRadioDisabled_)out->flags|=RTW_CONTROL_USER_RADIO_DISABLED;
    if(authorized())out->flags|=RTW_CONTROL_AUTHORIZED;
    auto&ic=core_.sc_ic;out->state=ic.ic_state;
    if(ic.ic_state==IEEE80211_S_SCAN&&!browseScanComplete_)out->flags|=RTW_CONTROL_SCANNING;
    out->usbError=usbError_;memcpy(out->mac,mac_.bytes,6);
    if(attached_&&ic.ic_bss){
        auto*n=ic.ic_bss;memcpy(out->bssid,n->ni_bssid,6);
        out->ssidLength=n->ni_esslen<=32?n->ni_esslen:0;memcpy(out->ssid,n->ni_essid,out->ssidLength);
        if(n->ni_chan&&n->ni_chan!=IEEE80211_CHAN_ANYC)out->channel=ieee80211_chan2ieee(&ic,n->ni_chan);
        if(ic.ic_state==IEEE80211_S_RUN){
            const uint64_t now=nowMS();
            out->rssi=rtw_signal_value(&signal_,n->ni_bssid,(uint16_t)out->channel,now);
            if(out->rssi&&now-signal_.sampled_ms>=RTW_SIGNAL_HELD_AGE_MS)
                out->flags|=RTW_CONTROL_SIGNAL_HELD;
        }
    }
    out->txPackets=txPackets_;out->rxPackets=rxPackets_;out->txErrors=txErrors_;out->rxErrors=rxErrors_;
    publishDiagnostics();
}
void RTWUSBController::publishDiagnosticCounter(const char *name, uint64_t value) {
    // Called while holding the controller's gate. Registry mutations can
    // allocate OSNumber objects; avoid them when the published value is stable.
    const auto *existing=OSDynamicCast(OSNumber,getProperty(name));
    if(rtw::diagnosticCounterNeedsWrite(existing!=nullptr,
        existing?existing->numberOfBits():0,
        existing?existing->unsigned64BitValue():0,value))
        setProperty(name,(unsigned long long)value,64);
}
void RTWUSBController::publishDiagnostics() {
    /* Control status is polled under the driver's gate. Publish counters here,
     * outside the RX hot path; no packet contents or key state are exported. */
    auto publish=[this](const char*name,uint64_t value){
        publishDiagnosticCounter(name,value);
    };
    /* Odd means a publication is in progress. The next even value commits
     * this device's snapshot; registry readers still need bracketing reads
     * before claiming an atomic snapshot. All writers run under our gate. */
    publish("RTWDiagPublicationGeneration",++diagnosticPublicationGeneration_);
    publish("RTWDiagCoreError",(uint64_t)(unsigned)core_.core_error);
    publish("RTWDiagAttached",attached_?1:0);
    publish("RTWDiagPresent",present_?1:0);
    publish("RTWDiagEnabled",enabled_?1:0);
    publish("RTWDiagRadioReady",radioReady_?1:0);
    publish("RTWDiagRunning",running_?1:0);
    publish("RTWDiagSleeping",sleeping_?1:0);
    publish("RTWDiagUserRadioDisabled",userRadioDisabled_?1:0);
    publish("RTWDiagStopping",stopping_?1:0);
    publish("RTWDiagClosing",closing_?1:0);
    if(family_==RTW_WIFI_RTL8814AU)publish8814RecoveryDiagnostics();
    else publishFamilyRecoveryDiagnostics();
    publishRateControlDiagnostics();
    /* No backend currently caches a complete, association-fresh effective
     * TX PHY tuple (rate, bandwidth and GI). Negotiated capability and RX MCS
     * are not an effective TX speed. Keep Ethernet metadata unknown. */
    publish("RTWDiagLinkSpeedKnown",0);
    publish("RTWDiagLinkSpeedBps",0);
    publish("SignalValidSamples",signal_.valid_samples);
    publish("SignalMissingPHY",signal_.missing_phy);
    publish("SignalInvalidPHY",signal_.invalid_phy);
    publish("SignalForeignFrames",signal_.foreign_frames);
    const uint64_t signalNow=nowMS();
    const bool samplePresent=signal_.valid&&signalNow>=signal_.sampled_ms;
    publish("SignalSampleAgeMS",samplePresent?signalNow-signal_.sampled_ms:UINT64_MAX);
    publish("SignalLastDBmMagnitude",samplePresent?(uint64_t)(-signal_.dbm):0);
    // Previously TX errors mixed USB faults and full software queues.
    // Keep the existing cumulative counter/ABI; publish separate causes.
    publish("RTWDiagTXQueueDrops",txQueueDrops_);
    publish("RTWDiagTXUSBTransferErrors",txUSBTransferErrors_);
    publish("RTWDiagTXLinkDrops",txLinkDrops_);
    publish("RTWDiagRXAggregates",rxDiag_.aggregates);
    publish("RTWDiagRXBytes",rxDiag_.bytes);
    publish("RTWDiagRXLastReadBytes",rxDiag_.lastReadBytes);
    publish("RTWDiagRXMaxReadBytes",rxDiag_.maxReadBytes);
    publish("RTWDiagRXAggregateLastErrorReadBytes",rxDiag_.lastAggregateErrorReadBytes);
    publish("RTWDiagRXAggregateErrors",rxDiag_.aggregateErrors);
    publish("RTWDiagRXAggregateTruncated",rxDiag_.aggregateTruncated);
    publish("RTWDiagRXAggregateMalformed",rxDiag_.aggregateMalformed);
    publish("RTWDiagRXAggregateTooMany",rxDiag_.aggregateTooMany);
    publish("RTWDiagRXAggregateBadArgument",rxDiag_.aggregateBadArgument);
    publish("RTWDiagRXAggregateLastErrorOffset",rxDiag_.lastAggregateErrorOffset);
    publish("RTWDiagRXAggregateLastErrorFrames",rxDiag_.lastAggregateErrorFrames);
    publish("RTWDiagRXPartialAggregates",rxDiag_.partialAggregates);
    publish("RTWDiagRXPartialPrefixFrames",rxDiag_.partialPrefixFrames);
    publish("RTWDiagRXPartialPrefixBytes",rxDiag_.partialPrefixBytes);
    publish("RTWDiagRXC2HReports",rxDiag_.c2h);
    publish("RTWDiagRXCRCDrops",rxDiag_.crcDrops);
    publish("RTWDiagRXICVDrops",rxDiag_.icvDrops);
    publish("RTWDiagRXInvalidFrameDrops",rxDiag_.invalidFrameDrops);
    publish("RTWDiagRXErrors",rxErrors_);
    publish("RTWDiagRXRejectSchema",2);
    publish("RTWDiagRXBlockAckFiltered",rxDiag_.blockAckFiltered);
    for(unsigned i=0;i<16;++i){
        char key[64];snprintf(key,sizeof(key),"RTWDiagRXRejectControlSubtype%u",i);
        publish(key,rxDiag_.rejectedControlSubtypes[i]);
    }
    static const char*const rejectNames[RTW_RX_REJECT_REASON_COUNT]={
        "Accepted","Length","Version","Header","Control","BARAuth",
        "BARContext","BARFlags","BARReceiver","BARTransmitter","Rate"};
    for(unsigned i=1;i<RTW_RX_REJECT_REASON_COUNT;++i){
        char key[64];snprintf(key,sizeof(key),"RTWDiagRXReject%s",rejectNames[i]);
        publish(key,rxDiag_.rejectedReasons[i]);
    }
    publish("RTWDiagRXRejectLastReason",rxDiag_.rejectLastReason);
    publish("RTWDiagRXRejectLastLength",rxDiag_.rejectLastLength);
    publish("RTWDiagRXRejectLastMonotonicMS",rxDiag_.rejectLastMS);
    publish("RTWDiagRXRejectLastType",rxDiag_.rejectLastType);
    publish("RTWDiagRXRejectLastSubtype",rxDiag_.rejectLastSubtype);
    publish("RTWDiagRXRejectLastFlags",rxDiag_.rejectLastFlags);
    publish("RTWDiagRXRejectLastVersion",rxDiag_.rejectLastVersion);
    publish("RTWDiagRXRejectLastSecurity",rxDiag_.rejectLastSecurity);
    publish("RTWDiagRXRejectLastSoftwareDecrypt",rxDiag_.rejectLastSoftwareDecrypt);
    publish("RTWDiagRXRejectLastPHY",rxDiag_.rejectLastPHY);
    publish("RTWDiagRXRejectLastPHYBytes",rxDiag_.rejectLastPHYBytes);
    publish("RTWDiagRXRejectLastReceiverMatchesLocal",rxDiag_.rejectLastReceiverMatch);
    publish("RTWDiagRXRejectLastTransmitterMatchesAP",rxDiag_.rejectLastTransmitterMatch);
    publish("RTWDiagRXRejectLastState",rxDiag_.rejectLastState);
    publish("RTWDiagRXRejectLastAuthorized",rxDiag_.rejectLastAuthorized);
    publish("RTWDiagRXRejectLastReadBytes",rxDiag_.rejectLastReadBytes);
    publish("RTWDiagRXRejectLastRate",rxDiag_.rejectLastRate);
    publish("RTWDiagRXRejectLastBAControl",rxDiag_.rejectLastBAControl);
    publish("RTWDiagRXRejectLastBAFragment",rxDiag_.rejectLastBAFragment);
    publish("RTWDiagRXHardwareDecryptDrops",rxDiag_.hardwareDecryptDrops);
    publish("RTWDiagRXAllocationDrops",rxDiag_.allocationDrops);
    publish("RTWDiagRXCopyDrops",rxDiag_.copyDrops);
    publish("RTWDiagRXNoNodeDrops",rxDiag_.noNodeDrops);
    publish("RTWDiagRXProtectedMPDUs",rxDiag_.protectedMPDUs);
    publish("RTWDiagRXMPDUsToNet80211",rxPackets_);
    publish("RTWDiagRXEthernetQueued",rxDiag_.ethernetQueued);
    publish("RTWDiagRXHandoffErrors",rxDiag_.handoffErrors);
    publish("RTWDiagNet80211InputPackets",stats_?stats_->inputPackets:0);
    publish("RTWDiagNet80211InputErrors",stats_?stats_->inputErrors:0);
    const auto&input=core_.sc_ic.ic_if.if_input_diag;
    publish("RTWDiagRXInputCalls",input.calls);
    publish("RTWDiagRXInputOfferedPackets",input.offeredPackets);
    publish("RTWDiagRXInputOfferedBytes",input.offeredBytes);
    publish("RTWDiagRXInputImmediateReturns",input.immediateReturns);
    publish("RTWDiagRXInputFlushCalls",input.flushCalls);
    publish("RTWDiagRXInputFlushPackets",input.flushPackets);
    publish("RTWDiagRXInputSubmissionMismatches",input.submissionMismatches);
    publish("RTWDiagRXInputNoIfnetCalls",input.noIfnetCalls);
    publish("RTWDiagRXInputInterfaceMatchesChild",attached_&&!closing_&&netif_&&core_.sc_ic.ic_if.iface==netif_?1:0);
    publish("RTWDiagRXNativeSampleCount",input.nativeSampleCount);
    publish("RTWDiagRXNativeSampleBatch",input.nativeSampleBatch);
    publish("RTWDiagRXNativeSampleOfferedPackets",input.nativeSampleOfferedPackets);
    publish("RTWDiagRXNativeSampleOfferedBytes",input.nativeSampleOfferedBytes);
    publish("RTWDiagRXNativeSampleImmediateReturns",input.nativeSampleImmediateReturns);
    publish("RTWDiagRXNativeSampleFlushPackets",input.nativeSampleFlushPackets);
    publish("RTWDiagRXNativeSampleIfnetStable",input.nativeSampleIfnetStable);
    /* These cumulative snapshots surround a sampled nonempty handoff. Keep
     * them separate from the later native KPI read below: DLIL may defer its
     * accounting. No counter is repaired or inferred from the offered batch. */
    const auto&before=input.nativeBefore;
    const auto&after=input.nativeAfter;
    const bool beforeValid=input.nativeSampleCount&&before.statsError==0;
    const bool afterValid=input.nativeSampleCount&&after.statsError==0;
    publish("RTWDiagRXNativeBeforeStatsValid",beforeValid?1:0);
    publish("RTWDiagRXNativeBeforeStatsError",(uint64_t)(uint32_t)before.statsError);
    publish("RTWDiagRXNativeBeforeIndex",before.index);
    publish("RTWDiagRXNativeBeforeSupportedCapabilities",before.supportedCapabilities);
    publish("RTWDiagRXNativeBeforeEnabledCapabilities",before.enabledCapabilities);
    publish("RTWDiagRXNativeBeforeInputPackets",beforeValid?before.packetsIn:0);
    publish("RTWDiagRXNativeBeforeInputBytes",beforeValid?before.bytesIn:0);
    publish("RTWDiagRXNativeBeforeInputErrors",beforeValid?before.errorsIn:0);
    publish("RTWDiagRXNativeBeforeOutputPackets",beforeValid?before.packetsOut:0);
    publish("RTWDiagRXNativeBeforeOutputBytes",beforeValid?before.bytesOut:0);
    publish("RTWDiagRXNativeBeforeOutputErrors",beforeValid?before.errorsOut:0);
    publish("RTWDiagRXNativeAfterStatsValid",afterValid?1:0);
    publish("RTWDiagRXNativeAfterStatsError",(uint64_t)(uint32_t)after.statsError);
    publish("RTWDiagRXNativeAfterIndex",after.index);
    publish("RTWDiagRXNativeAfterSupportedCapabilities",after.supportedCapabilities);
    publish("RTWDiagRXNativeAfterEnabledCapabilities",after.enabledCapabilities);
    publish("RTWDiagRXNativeAfterInputPackets",afterValid?after.packetsIn:0);
    publish("RTWDiagRXNativeAfterInputBytes",afterValid?after.bytesIn:0);
    publish("RTWDiagRXNativeAfterInputErrors",afterValid?after.errorsIn:0);
    publish("RTWDiagRXNativeAfterOutputPackets",afterValid?after.packetsOut:0);
    publish("RTWDiagRXNativeAfterOutputBytes",afterValid?after.bytesOut:0);
    publish("RTWDiagRXNativeAfterOutputErrors",afterValid?after.errorsOut:0);
    /* The IOKit statistics buffer and the BSD interface counters are distinct
     * observations. Read the interface KPI; never adjust either counter to
     * make the two agree. getIfnet() is valid only while the child is attached. */
    ifnet_stats_param nativeStats{};
    const auto nativeIfnet=attached_&&netif_&&!closing_?netif_->getIfnet():nullptr;
    const int nativeStatsError=nativeIfnet?ifnet_stat(nativeIfnet,&nativeStats):ENXIO;
    const bool nativeStatsValid=nativeStatsError==0;
    publish("RTWDiagNativeIfnetIndex",nativeIfnet?ifnet_index(nativeIfnet):0);
    const uint32_t nativeSupported=nativeIfnet?ifnet_capabilities_supported(nativeIfnet):0;
    const uint32_t nativeEnabled=nativeIfnet?ifnet_capabilities_enabled(nativeIfnet):0;
    publish("RTWDiagNativeIfnetSupportedCapabilities",nativeSupported);
    publish("RTWDiagNativeIfnetEnabledCapabilities",nativeEnabled);
    publish("RTWDiagNativeIfnetSkywalkEnabled",(nativeEnabled&IFCAP_SKYWALK)?1:0);
    publish("RTWDiagNativeIfnetStatsValid",nativeStatsValid?1:0);
    publish("RTWDiagNativeIfnetStatsError",(uint64_t)nativeStatsError);
    publish("RTWDiagNativeIfnetInputPackets",nativeStatsValid?nativeStats.packets_in:0);
    publish("RTWDiagNativeIfnetInputBytes",nativeStatsValid?nativeStats.bytes_in:0);
    publish("RTWDiagNativeIfnetInputErrors",nativeStatsValid?nativeStats.errors_in:0);
    publish("RTWDiagNativeIfnetOutputPackets",nativeStatsValid?nativeStats.packets_out:0);
    publish("RTWDiagNativeIfnetOutputBytes",nativeStatsValid?nativeStats.bytes_out:0);
    publish("RTWDiagNativeIfnetOutputErrors",nativeStatsValid?nativeStats.errors_out:0);
    const auto&s=core_.sc_ic.ic_stats;
    publish("RTWDiagNet80211TooShort",s.is_rx_tooshort);
    publish("RTWDiagNet80211NoBuffer",s.is_rx_nombuf);
    publish("RTWDiagNet80211WrongBSS",s.is_rx_wrongbss);
    publish("RTWDiagNet80211WrongDirection",s.is_rx_wrongdir);
    publish("RTWDiagNet80211Duplicates",s.is_rx_dup);
    publish("RTWDiagNet80211Unencrypted",s.is_rx_unencrypted);
    publish("RTWDiagNet80211ProtectionOff",s.is_rx_nowep);
    publish("RTWDiagNet80211DecryptFailures",s.is_rx_wepfail);
    publish("RTWDiagNet80211DecapFailures",s.is_rx_decap);
    publish("RTWDiagNet80211Unauthorized",s.is_rx_unauth);
    publish("RTWDiagNet80211CCMPReplays",s.is_ccmp_replays);
    publish("RTWDiagNet80211CCMPMICFailures",s.is_ccmp_dec_errs);
    /* Export existing stack events verbatim. no_buf includes both a missing
     * reorder buffer and an occupied duplicate slot, not just allocation.
     * Window events are not a one-to-one decomposition of inputErrors. */
    publish("RTWDiagNet80211RXBABelowWindow",s.is_ht_rx_frame_below_ba_winstart);
    publish("RTWDiagNet80211RXBAAboveWindow",s.is_ht_rx_frame_above_ba_winend);
    publish("RTWDiagNet80211RXBAWindowSlides",s.is_ht_rx_ba_window_slide);
    publish("RTWDiagNet80211RXBAWindowJumps",s.is_ht_rx_ba_window_jump);
    publish("RTWDiagNet80211RXBANoBuffer",s.is_ht_rx_ba_no_buf);
    publish("RTWDiagNet80211RXBAFramesLost",s.is_ht_rx_ba_frame_lost);
    publish("RTWDiagNet80211RXBAWindowGapTimeouts",s.is_ht_rx_ba_window_gap_timeout);
    publish("RTWDiagNet80211RXBATimeouts",s.is_ht_rx_ba_timeout);
    publish("RTWDiagNet80211TXBATimeouts",s.is_ht_tx_ba_timeout);
    publishCalibrationDiagnostics();
    publishScanDiagnostics();
    publishRXRecoveryDiagnostics();
    publishWpaDiagnostics();
    publishWpaRecoveryDiagnostics();
    publishPerformanceDiagnostics();
    const uint64_t publicationNow=nowMS();
    if(publicationNow>diagnosticPublicationMonotonicMS_)diagnosticPublicationMonotonicMS_=publicationNow;
    publish("RTWDiagPublicationMonotonicMS",diagnosticPublicationMonotonicMS_);
    publish("RTWDiagPublicationGeneration",++diagnosticPublicationGeneration_);
}
void RTWUSBController::publishScanDiagnostics() {
    auto publish=[this](const char*name,uint64_t value){publishDiagnosticCounter(name,value);};
    rtw::publishScanDiagnostics(scanDiag_,publish);
    auto&ic=core_.sc_ic;unsigned channel=0;
    if(attached_&&ic.ic_bss&&ic.ic_bss->ni_chan&&ic.ic_bss->ni_chan!=IEEE80211_CHAN_ANYC)
        channel=ieee80211_chan2ieee(&ic,ic.ic_bss->ni_chan);
    publish("RTWDiagCurrentChannel",rtw::scanDiagnosticChannelInRange(channel)?channel:0);
    publish("RTWDiagSupportedBandFlags",supported5GHzFlags());
    /* These are cached BSS records, distinct from the repeated beacon/probe
     * frame observations above. Bound the traversal independently of the
     * client's scan-results page size, without exporting any identity. */
    uint64_t bss24=0,bss5=0,bssUnknown=0;unsigned visited=0;
    auto*node=attached_?RB_MIN(ieee80211_tree,&ic.ic_tree):nullptr;
    while(node&&visited<1024){
        ++visited;unsigned cachedChannel=0;
        if(node->ni_chan&&node->ni_chan!=IEEE80211_CHAN_ANYC)
            cachedChannel=ieee80211_chan2ieee(&ic,node->ni_chan);
        const unsigned band=rtw::scanDiagnosticBand(cachedChannel);
        if(band==24)++bss24;else if(band==5)++bss5;else ++bssUnknown;
        node=RB_NEXT(ieee80211_tree,&ic.ic_tree,node);
    }
    publish("RTWDiagScanCacheBSS24",bss24);publish("RTWDiagScanCacheBSS5",bss5);
    publish("RTWDiagScanCacheBSSUnknown",bssUnknown);publish("RTWDiagScanCacheBSSVisited",visited);
    publish("RTWDiagScanCacheBSSTruncated",node?1:0);
}
void RTWUSBController::publishWpaDiagnostics() {
    /* Called under the control gate. Publish scalar progress only: no SSID,
     * key bytes, nonces, replay-counter values or packet contents. */
    auto publish=[this](const char*name,uint64_t value){publishDiagnosticCounter(name,value);};
    const auto&ic=core_.sc_ic;
    const auto*node=ic.ic_bss;
    publish("RTWDiagWPAProfileActive",joinRequested_?1:0);
    publish("RTWDiagWPARSNEnabled",(ic.ic_flags&IEEE80211_F_RSNON)?1:0);
    publish("RTWDiagWPAPSKConfigured",(ic.ic_flags&IEEE80211_F_PSK)?1:0);
    publish("RTWDiagWPAEAPOLReceived",ic.ic_stats.is_rx_eapol_key);
    publish("RTWDiagWPAEAPOLReplays",ic.ic_stats.is_rx_eapol_replay);
    publish("RTWDiagWPAEAPOLBadMIC",ic.ic_stats.is_rx_eapol_badmic);
    publish("RTWDiagWPASupplicantState",node?node->ni_rsn_supp_state:0);
    publish("RTWDiagWPAPortValid",node?node->ni_port_valid:0);
    publish("RTWDiagWPAProtocol",node?node->ni_rsnprotos:0);
    publish("RTWDiagWPACipher",node?node->ni_rsncipher:0);
    publish("RTWDiagWPAAssocStatus",ic.ic_assoc_status);
    publish("RTWDiagWPADeauthReason",ic.ic_deauth_reason);
    publish("RTWDiagWPAProtectionMode",ic.ic_protmode);
}
void RTWUSBController::channelMap(RTWControlChannelMap*out) const {
    bzero(out,sizeof(*out));out->version=RTW_CONTROL_VERSION;
    if(!attached_)return;
    for(unsigned channel=1;channel<256;++channel) {
        const auto flags=core_.sc_ic.ic_channels[channel].ic_flags;
        if(flags&(channel<=14?IEEE80211_CHAN_2GHZ:IEEE80211_CHAN_5GHZ))
            out->channels[channel/8U]|=(uint8_t)(1U<<(channel%8U));
    }
}
void RTWUSBController::scanResults(RTWControlScanResults*out) {
    bzero(out,sizeof(*out));out->version=RTW_CONTROL_VERSION;if(!attached_)return;
    ieee80211_node*node=RB_MIN(ieee80211_tree,&core_.sc_ic.ic_tree);
    unsigned visited=0;
    while(node&&visited++<1024){
        if(out->count==RTW_CONTROL_MAX_NETWORKS){out->truncated=1;break;}
        if(node->ni_esslen<=32&&node->ni_chan&&node->ni_chan!=IEEE80211_CHAN_ANYC){
            auto&r=out->records[out->count++];r.ssidLength=node->ni_esslen;memcpy(r.ssid,node->ni_essid,r.ssidLength);memcpy(r.bssid,node->ni_bssid,6);
            r.channel=(uint8_t)ieee80211_chan2ieee(&core_.sc_ic,node->ni_chan);r.rssi=node->ni_rssi?(int16_t)node->ni_rssi-100:0;
            /* A CCMP *pairwise* cipher alone does not prove this station can
             * connect: group TKIP and mandatory PMF are unsupported by the
             * selected WPA2-PSK/CCMP configuration. Only report a compatible
             * network when the complete RSN policy is satisfied. */
            const rtw_network_security capabilities{
                static_cast<uint8_t>((node->ni_capinfo&IEEE80211_CAPINFO_PRIVACY)!=0),
                static_cast<uint8_t>((node->ni_rsnprotos&IEEE80211_PROTO_RSN)!=0),
                static_cast<uint8_t>((node->ni_rsnakms&IEEE80211_AKM_PSK)!=0),
                static_cast<uint8_t>((node->ni_rsnciphers&IEEE80211_CIPHER_CCMP)!=0),
                static_cast<uint8_t>(node->ni_rsngroupcipher==IEEE80211_CIPHER_CCMP),
                static_cast<uint8_t>((node->ni_rsncaps&IEEE80211_RSNCAP_MFPR)!=0)
            };
            if(capabilities.privacy)r.securityFlags|=RTW_CONTROL_SECURITY_PRIVACY;
            if(rtw_network_security_classify(&capabilities)==RTW_NETWORK_WPA2_PSK_CCMP)
                r.securityFlags|=RTW_CONTROL_SECURITY_WPA2_PSK|RTW_CONTROL_SECURITY_CCMP;
            else r.securityFlags|=RTW_CONTROL_SECURITY_UNSUPPORTED;
        }
        node=RB_NEXT(ieee80211_tree,&core_.sc_ic.ic_tree,node);
    }
    if(node&&visited>=1024)out->truncated=1;
}
IOReturn RTWUSBController::handleControl(ControlCall*call) {
    if(!call||rtw_control_validate_request(call->selector,call->input,call->length)!=RTW_CONTROL_VALID||!call->outputLength||!call->output||*call->outputLength<rtw_control_output_size(call->selector))return kIOReturnBadArgument;
    size_t size=rtw_control_output_size(call->selector);bzero(call->output,size);*call->outputLength=size;
    if(call->selector==RTW_CONTROL_STATUS){status(static_cast<RTWControlStatus*>(call->output));return kIOReturnSuccess;}
    if(call->selector==RTW_CONTROL_SCAN_RESULTS){scanResults(static_cast<RTWControlScanResults*>(call->output));return kIOReturnSuccess;}
    if(call->selector==RTW_CONTROL_CHANNEL_MAP){channelMap(static_cast<RTWControlChannelMap*>(call->output));return kIOReturnSuccess;}
    /* Experimental radio-ABI bridge: bench access to the callPlatformFunction
     * surface before any layer kext exists. Status/channels are read-only; TX
     * carries the radio-side guards (NotReady/Busy/NoResources) verbatim. */
    if(call->selector==RTW_CONTROL_RADIO_STATUS){
        auto*out=static_cast<RTWControlRadioStatus*>(call->output);
        struct rtl_radio_status radio{};
        radioStatus(&radio);
        out->version=RTW_CONTROL_VERSION;out->build=3;out->state=radio.state;
        out->flags=(radioDataHook_?1U:0U)|(radioAwdlHook_?2U:0U);
        out->channel=radio.channel;out->band=radio.band;out->bssBw=radio.bss_bw;out->center=radio.center;
        out->rssiDbm=radio.rssi_dbm;memcpy(out->bssid,radio.bssid,6);
        out->ssidLength=radio.ssid_len;memcpy(out->ssid,radio.ssid,radio.ssid_len);
        out->gates=(supports88Band(true)?1U:0U)|(r88BoardKnown_?2U:0U)|
            (r88Core_.board.features_valid?4U:0U)|(r88Core_.board.active_rf_paths==1?8U:0U);
        out->boardRfPaths=r88Core_.board.rf_paths;
        out->reserved[0]=(uint32_t)radioOffchLastErr_;
        out->reserved[1]=radioOffchLastStep_;
        return kIOReturnSuccess;
    }
    if(call->selector==RTW_CONTROL_RADIO_TX_80211){
        const auto*frame=static_cast<const RTWControlRadioFrame*>(call->input);
        uint32_t length=frame->length;
        return radioTx80211(frame->frame,&length);
    }
    if(call->selector==RTW_CONTROL_RADIO_CHANNELS){
        auto*out=static_cast<RTWControlRadioChannels*>(call->output);
        struct rtl_radio_chan plan[64]{};
        uint32_t count=64;
        radioChannels(plan,&count);
        out->version=RTW_CONTROL_VERSION;out->count=count;
        for(uint32_t i=0;i<count;++i){out->channel[i]=plan[i].channel;out->band[i]=plan[i].band;out->passive[i]=plan[i].passive;}
        return kIOReturnSuccess;
    }
    if(call->selector==RTW_CONTROL_RADIO_SET_CHANNEL){
        const auto*in=static_cast<const RTWControlRadioChannel*>(call->input);
        uint32_t channel=in->channel;
        return radioSetChannel(&channel);
    }
    if(call->selector==RTW_CONTROL_RADIO_OFFCH){
        const auto*in=static_cast<const RTWControlRadioChannel*>(call->input);
        uint32_t channel=in->channel;
        return radioAwdlOffch(&channel);
    }
    if(call->selector==RTW_CONTROL_RADIO_RATE){
        const auto*in=static_cast<const RTWControlRadioChannel*>(call->input);
        uint32_t rate=in->channel;
        return radioAwdlRate(&rate);
    }
    if(call->selector==RTW_CONTROL_RADIO_TXSTAT){
        auto*out=static_cast<RTWControlRadioTxStat*>(call->output);
        struct rtl_radio_awdl_txstat stat{};
        const IOReturn result=radioAwdlTxStat(&stat);
        out->version=RTW_CONTROL_VERSION;out->clean=stat.clean;out->retried=stat.retried;
        out->retried2=stat.retried2;out->lost=stat.lost;out->rate=stat.rate;out->reports=stat.reports;
        return result;
    }
    auto*reply=static_cast<RTWControlReply*>(call->output);reply->version=RTW_CONTROL_VERSION;
    if(call->selector==RTW_CONTROL_LEAVE){
        userRadioDisabled_=true;
        // Sleep already quiesced the radio. Erase only host intent while
        // asleep, preserving any deferred USB stop/drain and its result.
        if(sleeping_)eraseProfile();else quiesce(true);
        return kIOReturnSuccess;
    }
    if(!attached_||!present_||sleeping_||usbError_!=kIOReturnSuccess)return kIOReturnNotReady;
    /* SCAN is a foreground operation: net80211_begin_scan clears BSS keys.
     * The app's last idle STATUS can precede an in-kernel recovery. Admit
     * against the live, serialized state before any backend recovery/reset,
     * preserving authentication, association and an established connection.
     * Faulted/stopped radios still reach their normal recovery path below. */
    if(call->selector==RTW_CONTROL_SCAN&&running_&&!stopping_&&!core_.core_error&&
       core_.sc_ic.ic_state>=IEEE80211_S_AUTH)return kIOReturnBusy;
    if(family_==RTW_WIFI_RTL8814AU&&
       (call->selector==RTW_CONTROL_SCAN||call->selector==RTW_CONTROL_JOIN)){
        const int recovery=recover8814ForControl();if(recovery)return fromErrno(recovery);
    }
    if(family_!=RTW_WIFI_RTL8814AU&&
       (call->selector==RTW_CONTROL_SCAN||call->selector==RTW_CONTROL_JOIN)){
        const int recovery=recoverFamilyForControl();if(recovery)return fromErrno(recovery);
    }
    if(core_.core_error)return kIOReturnNotReady;
    if(call->selector==RTW_CONTROL_JOIN){
        const auto*join=static_cast<const RTWControlJoin*>(call->input);
        userRadioDisabled_=false;
        quiesce(true);
        ieee80211_wpaparams parameters{};parameters.i_enabled=1;parameters.i_protos=IEEE80211_WPA_PROTO_WPA2;parameters.i_akms=IEEE80211_WPA_AKM_PSK;parameters.i_ciphers=IEEE80211_WPA_CIPHER_CCMP;parameters.i_groupcipher=IEEE80211_WPA_CIPHER_CCMP;
        int error=ieee80211_ioctl_setwpaparms(&core_.sc_ic,&parameters);
        if(error&&error!=ENETRESET)return fromErrno(error);
        memcpy(core_.sc_ic.ic_psk,join->pmk,32);core_.sc_ic.ic_flags|=IEEE80211_F_PSK;
        core_.sc_ic.ic_des_esslen=join->ssidLength;memcpy(core_.sc_ic.ic_des_essid,join->ssid,join->ssidLength);joinRequested_=true;
        IOReturn result=enableStation();if(result!=kIOReturnSuccess)quiesce(true);return result;
    }
    if(call->selector==RTW_CONTROL_SCAN){
        if(rxRecovery_.pending)return kIOReturnBusy;
        userRadioDisabled_=false;
        if(!running_)return enableStation();
        ieee80211_begin_scan(&core_.sc_ic.ic_if);
        return rtwn_io_error(&core_)?kIOReturnIOError:kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}
IOReturn RTWUSBController::gated(OSObject*object,void*operation,void*a,void*,void*) {
    auto*s=static_cast<RTWUSBController*>(object);
    if(s->closing_&&(uintptr_t)operation!=Shutdown&&(uintptr_t)operation!=TeardownReady){
        if((uintptr_t)operation==Output){auto*call=static_cast<OutputCall*>(a);call->consumed=true;if(call->packet)mbuf_freem(call->packet);return kIOReturnOutputDropped;}
        if((uintptr_t)operation==Disable||(uintptr_t)operation==Terminated)return kIOReturnSuccess;
        return kIOReturnNotReady;
    }
    switch((uintptr_t)operation){
    case Initialize:return s->initializePlatform();
    case Shutdown:s->shutdownPlatform();return kIOReturnSuccess;
    case TeardownReady:s->teardownReady_=true;s->scheduleDeferredCleanup();return kIOReturnSuccess;
    case Enable:return s->userRadioDisabled_?kIOReturnSuccess:s->enableStation();
    // IOEthernetInterface disables before a PM power drop. Preserve the
    // configured profile here; explicit LEAVE owns manual radio-off/erasure.
    case Disable:s->quiesce(false);return kIOReturnSuccess;
    case Output:{
        auto*call=static_cast<OutputCall*>(a);mbuf_t packet=call->packet;
        call->consumed=true;
        if(s->stopping_||!s->authorized()||!packet){
            if(packet){mbuf_freem(packet);++s->txLinkDrops_;}
            return kIOReturnOutputDropped;
        }
        auto*queue=s->core_.sc_ic.ic_if.if_snd.queue;
        if(!queue){
            mbuf_freem(packet);++s->txErrors_;++s->txQueueDrops_;
            if(s->stats_)++s->stats_->outputErrors;
            return kIOReturnOutputDropped;
        }
        if(!queue->lockEnqueue(packet)){
            // Retry returns this untouched mbuf to IOGatedOutputQueue. The
            // completion path services that queue after inner capacity opens.
            call->consumed=false;return kIOReturnOutputStall;
        }
        /* AWDL off-channel slot: the radio is elsewhere, so hold the data
         * queues (ABI rule) instead of letting send88Frame drop them. */
        if(s->radioOffchState_)return kIOReturnOutputSuccess;
        rtwn_start(&s->core_.sc_ic.ic_if);return kIOReturnOutputSuccess;
    }
    case Control:return s->handleControl(static_cast<ControlCall*>(a));
    case RadioABI:{
        auto*call=static_cast<RadioABICall*>(a);
        s->radioABIEntry(call);
        return call->result;
    }
    case Terminated:
        // Reject new work before quiescing; stop() may follow synchronously
        // when our provider is closed by the termination notification.
        s->closing_=true;s->present_=false;
        s->fault(kIOReturnNoDevice);s->quiesce(true);
        return kIOReturnSuccess;
    case Sleep:s->quiesce(false);s->sleeping_=true;return kIOReturnSuccess;
    case Wake:s->sleeping_=false;/* IOEthernetInterface re-enables after the usable-state notification. */return kIOReturnSuccess;
    default:return kIOReturnBadArgument;
    }
}
IOCommandGate *RTWUSBController::copyGate(IOWorkLoop **loop) {
    *loop=nullptr;if(!lifecycleLock_)return nullptr;
    IOLockLock(lifecycleLock_);IOCommandGate*gate=gate_;
    if(gate&&loop_){gate->retain();*loop=loop_;(*loop)->retain();}else gate=nullptr;
    IOLockUnlock(lifecycleLock_);return gate;
}
IOReturn RTWUSBController::enable(IONetworkInterface*interface) {
    IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);if(!gate||interface!=netif_){if(gate)gate->release();if(lease)lease->release();return kIOReturnNotReady;}
    IOReturn result=gate->runAction(gated,(void*)Enable);gate->release();lease->release();return result;
}
IOReturn RTWUSBController::disable(IONetworkInterface*) {
    IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);if(!gate)return kIOReturnNotReady;
    IOReturn result=gate->runAction(gated,(void*)Disable);gate->release();lease->release();return result;
}
UInt32 RTWUSBController::outputPacket(mbuf_t packet,void*) {
    IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);if(!gate){if(packet)mbuf_freem(packet);return kIOReturnOutputDropped;}
    OutputCall call{packet,false};
    IOReturn result=gate->runAction(gated,(void*)Output,&call);gate->release();lease->release();
    if(result==kIOReturnOutputStall&&!call.consumed)return kIOReturnOutputStall;
    if(!call.consumed){if(packet)mbuf_freem(packet);return kIOReturnOutputDropped;}
    return result==kIOReturnOutputSuccess?kIOReturnOutputSuccess:kIOReturnOutputDropped;
}
IOReturn RTWUSBController::controlRequest(uint32_t selector,const void*input,size_t length,void*output,size_t*outputLength) {
    IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);if(!gate||isInactive()){if(gate)gate->release();if(lease)lease->release();return kIOReturnNotReady;}
    ControlCall call{selector,input,length,output,outputLength};IOReturn result=gate->runAction(gated,(void*)Control,&call);gate->release();lease->release();return result;
}

IOReturn RTWUSBController::newUserClient(task_t task,void*security,UInt32 type,OSDictionary*properties,IOUserClient**handler) {
    if(!handler)return kIOReturnBadArgument;*handler=nullptr;if(isInactive()||!attached_)return kIOReturnNotReady;
    auto*client=new RTWUserClient;if(!client)return kIOReturnNoMemory;
    if(!client->initWithTask(task,security,type,properties)){client->release();return kIOReturnNotPrivileged;}
    if(!client->attach(this)){client->release();return kIOReturnError;}
    if(!client->start(this)){client->detach(this);client->release();return kIOReturnError;}
    *handler=client;return kIOReturnSuccess;
}
IOReturn RTWUSBController::message(UInt32 type,IOService*provider,void*argument) {
    if((type==kIOMessageServiceIsTerminated||type==kIOMessageServiceIsRequestingClose)&&(provider==usb_||is8192DUUSBProvider(provider))){
        // IOService does not call stop() on an opened client until that client
        // closes the terminated provider. Keep ourselves alive across close():
        // it can synchronously invoke stop() and trigger last-reference teardown.
        retain();
        IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);
        bool quiesced=false;
        if(gate){
            quiesced=gate->runAction(gated,(void*)Terminated)==kIOReturnSuccess;
            gate->release();lease->release();
        }
        IOReturn result=super::message(type,provider,argument);
        // Never close the provider under our workloop gate: close() may run
        // stop(), whose shutdown path must acquire that same gate.
        if(quiesced){closeUSBProvider();close8192DUProviders();}
        // When the gate is unavailable, releasePlatform() owns the fallback
        // close. Do not close before outstanding work has been quiesced.
        release();
        return result;
    }
    return super::message(type,provider,argument);
}
IOReturn RTWUSBController::setPowerState(unsigned long state,IOService*) {
    IOWorkLoop*lease=nullptr;auto*gate=copyGate(&lease);if(gate){gate->runAction(gated,(void*)(state?Wake:Sleep));gate->release();lease->release();}return kIOPMAckImplied;
}
IOReturn RTWUSBController::registerWithPolicyMaker(IOService*policyMaker) {
    if(!policyMaker)return kIOReturnBadArgument;
    if(powerRegistrationAttempted_)return powerManaged_?kIOReturnSuccess:powerRegistrationResult_;
    powerRegistrationAttempted_=true;
    // IONetworkController initializes and joins PM in super::start(), then
    // invokes this hook from attachInterface(). Its default hook stops PM.
    // Fully initialize once: two adapters may register concurrently.
    static IOPMPowerState states[2]={
        {1,0,0,0,0,0,0,0,0,0,0,0},
        {1,kIOPMPowerOn|kIOPMDeviceUsable,kIOPMPowerOn,kIOPMPowerOn,0,0,0,0,0,0,0,0}
    };
    powerRegistrationResult_=policyMaker->registerPowerDriver(this,states,2);
    if(powerRegistrationResult_!=kIOReturnSuccess)return powerRegistrationResult_;
    powerManaged_=true;
    powerRegistrationResult_=policyMaker->changePowerStateTo(1);
    // Once registered, callbacks may already be waiting for our workloop.
    // Return success to prepare(), which otherwise calls PMstop under that
    // same gate. start() handles a failed power request after attachment.
    return kIOReturnSuccess;
}
void RTWUSBController::stopPowerManagement() {
    if(powerManaged_){PMstop();powerManaged_=false;}
}
void RTWUSBController::reportStartStage(const char *stage, IOReturn result) {
    // Preserve the last start stage on the USB provider even if start fails
    // and IOKit destroys this controller. No SSID or key material is logged.
    setProperty("RTWStartStage",stage);
    setProperty("RTWStartResult",(unsigned long long)(uint32_t)result,32);
    if(auto *provider=getProvider()){
        provider->setProperty("RTWStartStage",stage);
        provider->setProperty("RTWStartResult",(unsigned long long)(uint32_t)result,32);
    }
    IOLog("[TahoeRealtekWiFi 0.14.9] start stage=%s result=0x%08x\n",stage,(unsigned)result);
}
bool RTWUSBController::start(IOService*provider) {
    reportStartStage("entry");
    IOReturn runtimeResult=RTWNet80211Acquire(&loop_);
    if(runtimeResult!=kIOReturnSuccess){reportStartStage("stack-runtime",runtimeResult);return false;}runtimeLease_=true;
    lifecycleLock_=IOLockAlloc();completionLock_=IOSimpleLockAlloc();
    // The priority-only allocator is exported by the private KPI on Tahoe.
    // The public Mach allocator preserves the same priority and zero options.
    cleanupCall_=thread_call_allocate_with_options(deferredCleanup,this,THREAD_CALL_PRIORITY_KERNEL,0);
    if(!lifecycleLock_||!loop_||!completionLock_||!cleanupCall_){reportStartStage("locks-workloop",kIOReturnNoMemory);releasePlatform();return false;}
    if(!super::start(provider)){reportStartStage("network-super-start",kIOReturnError);releasePlatform();return false;}
    // Immutable identity is published once, independently of periodic counters.
    setProperty("RTWDiagDriverBuild",(unsigned long long)67,64);
    usb_=OSDynamicCast(IOUSBHostInterface,provider);
    if(!usb_||!usb_->open(this)){reportStartStage("usb-open",kIOReturnNotOpen);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    usbOpened_=present_=true;
    gate_=IOCommandGate::commandGate(this);completionEvent_=IOInterruptEventSource::interruptEventSource(this,completionAction);
    scanTimer_=IOTimerEventSource::timerEventSource(this,scanAction);calibTimer_=IOTimerEventSource::timerEventSource(this,calibAction);watchdogTimer_=IOTimerEventSource::timerEventSource(this,watchdogAction);
    if(!gate_||!completionEvent_||!scanTimer_||!calibTimer_||!watchdogTimer_||loop_->addEventSource(gate_)!=kIOReturnSuccess||loop_->addEventSource(completionEvent_)!=kIOReturnSuccess||loop_->addEventSource(scanTimer_)!=kIOReturnSuccess||loop_->addEventSource(calibTimer_)!=kIOReturnSuccess||loop_->addEventSource(watchdogTimer_)!=kIOReturnSuccess){reportStartStage("event-sources",kIOReturnNoResources);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    completionEvent_->enable();rtw_transfer_reset(&ledger_);
    if(!taskq_is_initialized(systq)){reportStartStage("taskqueue",kIOReturnNoResources);gate_->runAction(gated,(void*)Shutdown);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    if(gate_->runAction(gated,(void*)Initialize)!=kIOReturnSuccess){gate_->runAction(gated,(void*)Shutdown);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    OSDictionary*media=OSDictionary::withCapacity(1);IONetworkMedium*automatic=IONetworkMedium::medium(kIOMediumEthernetAuto,0);
    bool mediumOK=media&&automatic&&IONetworkMedium::addMedium(media,automatic)&&publishMediumDictionary(media)&&setSelectedMedium(automatic);
    if(automatic)automatic->release();if(media)media->release();
    IONetworkInterface*interface=nullptr;
    /* NOTE (reverted): skipping the ifnet when rtlair=2 broke the driver's
     * own scan/join machinery (ieee80211_begin_scan needs the attached,
     * UP ifnet; without it neither the custom app nor the ABI scans
     * return results). The competing-ifnet theory is dead: DrogaBox's
     * working setup has BOTH ifnets (driver en2 + the native one) on
     * 26.7. The ifnet-materialization blocker must be found elsewhere. */
    if(!mediumOK||!attachInterface(&interface,false)){stopPowerManagement();reportStartStage("ethernet-attach",kIOReturnError);gate_->runAction(gated,(void*)Shutdown);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    netif_=OSDynamicCast(IOEthernetInterface,interface);
    if(!netif_){stopPowerManagement();reportStartStage("ethernet-type",kIOReturnUnsupported);detachInterface(interface,true);interface->release();gate_->runAction(gated,(void*)Shutdown);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    if(!powerManaged_||powerRegistrationResult_!=kIOReturnSuccess){const IOReturn error=powerRegistrationResult_==kIOReturnSuccess?kIOReturnNotReady:powerRegistrationResult_;stopPowerManagement();reportStartStage("power-register",error);gate_->runAction(gated,(void*)Shutdown);releasePlatform();super::stop(provider);markTeardownReady();return false;}
    super::setLinkStatus(kIONetworkLinkValid);reportStartStage("ready");registerService();netif_->registerService();return true;
}
void RTWUSBController::shutdownPlatform() {
    closing_=true;quiesce(true);
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);bool drained=rtw_transfer_drained(&ledger_);IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(!drained){if(!retainedForPending_)retain();retainedForPending_=true;IOLog("[TahoeRealtekWiFi] USB abort has not drained; retaining driver resources to prevent unsafe teardown\n");return;}
    if(attached_){rtwn_detach(&core_,0);attached_=false;ether_ifdetach(&core_.sc_ic.ic_if);}
    /* Detach the Ethernet child outside our gate: its synchronous disable
     * callback may run on another networking thread and acquire this gate. */
    macReady_=false;
}
void RTWUSBController::closeUSBProvider() {
    IOUSBHostInterface*provider=nullptr;
    // close() may synchronously reenter stop(). Claim the open under a lock
    // *before* calling it, so releasePlatform() cannot close it again.
    if(lifecycleLock_)IOLockLock(lifecycleLock_);
    if(usb_&&usbOpened_){
        provider=usb_;
        usbOpened_=false;
        provider->retain();
    }
    if(lifecycleLock_)IOLockUnlock(lifecycleLock_);
    if(provider){provider->close(this);provider->release();}
}
void RTWUSBController::releasePlatform() {
    if(retainedForPending_)return;
    if(completionLock_)freeTransfers();
    if(cleanupCall_){thread_call_free(cleanupCall_);cleanupCall_=nullptr;}
    if(netif_){detachInterface(netif_,true);netif_->release();netif_=nullptr;}stats_=nullptr;
    IOCommandGate *oldGate=gate_;
    if(lifecycleLock_){IOLockLock(lifecycleLock_);oldGate=gate_;gate_=nullptr;IOLockUnlock(lifecycleLock_);}
    if(loop_){
        IOEventSource*events[]={scanTimer_,calibTimer_,watchdogTimer_,completionEvent_,oldGate};
        for(auto*event:events)if(event){if(event!=oldGate)event->disable();if(event->getWorkLoop()==loop_)loop_->removeEventSource(event);event->release();}
    }
    scanTimer_=calibTimer_=watchdogTimer_=nullptr;completionEvent_=nullptr;gate_=nullptr;
    if(rxPipe_){rxPipe_->release();rxPipe_=nullptr;}for(auto*&p:txPipes_)if(p){p->release();p=nullptr;}
    closeUSBProvider();
    if(lifecycleLock_)IOLockLock(lifecycleLock_);
    usb_=nullptr;usbOpened_=present_=false;
    if(lifecycleLock_)IOLockUnlock(lifecycleLock_);
    if(completionLock_){IOSimpleLockFree(completionLock_);completionLock_=nullptr;}
    // The optional coexistence timer is retained by the shared WorkLoop.
    // Remove it while this controller still holds its WorkLoop reference.
    release88Storage();
    if(loop_){loop_->release();loop_=nullptr;}
    if(acPHYStorage_){IOFree(acPHYStorage_,acPHYSize_);acPHYStorage_=nullptr;acPHYSize_=0;acCore_.phy=nullptr;}
    release8723Storage();
    release8710BUStorage();
    release8192FUStorage();
    release8192DUStorage();
    release8812Storage();
    if(runtimeLease_){runtimeLease_=false;RTWNet80211Release();}
}
void RTWUSBController::stop(IOService*provider) {
    stopPowerManagement();
    if(gate_)gate_->runAction(gated,(void*)Shutdown);
    releasePlatform();super::stop(provider);markTeardownReady();
}
void RTWUSBController::free() {releasePlatform();if(lifecycleLock_){IOLockFree(lifecycleLock_);lifecycleLock_=nullptr;}super::free();}
#include "RTW8814Bus.inc"
#include "RTW8814Backend.inc"
#include "RTW8814Recovery.inc"
#include "RTW8812Backend.inc"
#include "RTW88Backend.inc"
#include "RTW8192DUBackend.inc"
#include "RTW8192FUBackend.inc"
#include "RTW8710BUBackend.inc"
#include "RTW8723BUBackend.inc"
#include "RTWFamilyRecovery.inc"

// Called while the shared WorkLoop is gated. Never free a WorkLoop, an
// Ethernet child or a USB descriptor from its own completion callback.
void RTWUSBController::scheduleDeferredCleanup() {
    if(!retainedForPending_||!teardownReady_||cleanupQueued_||!cleanupCall_||!completionLock_)return;
    IOInterruptState lock=IOSimpleLockLockDisableInterrupt(completionLock_);
    const bool drained=rtw_transfer_drained(&ledger_);
    IOSimpleLockUnlockEnableInterrupt(completionLock_,lock);
    if(!drained)return;
    cleanupQueued_=true;
    thread_call_enter(cleanupCall_);
}
void RTWUSBController::markTeardownReady() {
    IOWorkLoop* lease=nullptr;auto* gate=copyGate(&lease);
    if(gate){gate->runAction(gated,(void*)TeardownReady);gate->release();lease->release();}
}
void RTWUSBController::deferredCleanup(thread_call_param_t argument,thread_call_param_t) {
    auto* controller=static_cast<RTWUSBController*>(argument);
    IOWorkLoop* lease=nullptr;auto* gate=controller->copyGate(&lease);
    if(!gate)return; // The deferred retain keeps all resources until a gate exists.
    gate->runAction(gated,(void*)Shutdown);
    // The worker cannot run until drainCompletions has returned. No new
    // submissions are possible after closing_, and schedule checked drained.
    controller->retainedForPending_=false;
    gate->release();lease->release();
    controller->releasePlatform();
    controller->release(); // Balance shutdownPlatform's deferred retain exactly once.
}

/* ===================== RTL radio ABI =====================
 * Surface for an external IO80211 layer kext (DrogaBox's RTLAirLayer or a
 * port of it): it adopts the radio through callPlatformFunction with the
 * rtlRadio* symbols of include/rtw/RTLRadioABI.h. Every entry runs on the
 * controller's command gate so it serializes with USB I/O and net80211.
 * Milestone 1 implements the infra ops. The AWDL ops still answer
 * kIOReturnUnsupported; they need per-chip TX-report/ad-hoc-port/off-channel
 * work in the RTW88 backend (see docs plan). */
static RTWUSBController *rtwRadioABIOwner = nullptr;

extern "C" int rtw_radio_rx_hook_active(void) {
    RTWUSBController *s = rtwRadioABIOwner;
    return s && s->radioHookActive() ? 1 : 0;
}

extern "C" int rtw_radio_rx_hook_deliver(void *mbuf) {
    RTWUSBController *s = rtwRadioABIOwner;
    rtl_radio_rx_fn hook = nullptr;
    void *ctx = nullptr;
    if (s) {
        /* Read under the completion path's serialization: receive() runs on
         * the driver's completion context, so the member pair is stable. */
        hook = s->radioHookFn();
        ctx = s->radioHookCtx();
    }
    if (!hook) return 0;
    hook(ctx, mbuf);            /* the hook now owns the mbuf */
    return 1;
}

bool RTWUSBController::radioABIAdmits() const {
    /* Only dual-band station backends: AWDL lives on the 5 GHz social
     * channels, so a 2.4-only adapter must not be adopted by the layer. */
    return profile_ != nullptr &&
        (is88Family() || is8812Family() || family_ == RTW_WIFI_RTL8814AU);
}

IOReturn RTWUSBController::dispatchRadioABI(const char *fn, void *p1, void *p2) {
    if (!fn) return kIOReturnBadArgument;
    RadioABICall call{fn, p1, p2, kIOReturnNotReady};
    IOWorkLoop *lease = nullptr;
    IOCommandGate *gate = copyGate(&lease);
    if (!gate) return kIOReturnNotReady;
    IOReturn result = gate->runAction(gated, (void *)RadioABI, &call);
    gate->release();
    lease->release();
    return result == kIOReturnSuccess ? call.result : result;
}

IOReturn RTWUSBController::callPlatformFunction(const OSSymbol *functionName, bool waitForFunction,
                                                void *p1, void *p2, void *p3, void *p4) {
    const char *fn = functionName ? functionName->getCStringNoCopy() : nullptr;
    if (fn && strncmp(fn, "rtlRadio", 8) == 0)
        return dispatchRadioABI(fn, p1, p2);
    return super::callPlatformFunction(functionName, waitForFunction, p1, p2, p3, p4);
}

IOReturn RTWUSBController::callPlatformFunction(const char *functionName, bool waitForFunction,
                                                void *p1, void *p2, void *p3, void *p4) {
    if (functionName && strncmp(functionName, "rtlRadio", 8) == 0)
        return dispatchRadioABI(functionName, p1, p2);
    return super::callPlatformFunction(functionName, waitForFunction, p1, p2, p3, p4);
}

void RTWUSBController::radioABIEntry(RadioABICall *call) {
    call->result = kIOReturnUnsupported;
    if (!call->fn || !radioABIAdmits()) return;
    const char *fn = call->fn;
    void *p1 = call->p1, *p2 = call->p2;
    auto&ic = core_.sc_ic;
    if (strcmp(fn, RTL_RADIO_FN_ABI) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        *(uint32_t *)p1 = RTL_RADIO_ABI;
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_MAC) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        memcpy(p1, mac_.bytes, 6);
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_SET_MAC) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        /* DrogaBox builds 4.15+ accept it. REQUIRED for the native UI: the
         * layer's interface carries macOS's (randomized) identity and the
         * radio must match it over the air. With this stubbed, the
         * association stayed on the efuse MAC while the DHCP client was the
         * interface's MAC — every hotspot's lease filter drops that
         * mismatch (boots 9-13: DHCP DISCOVER left, no OFFER, 169.254).
         * Update all three identities together: the firmware's station
         * entry (r88StationMAC_ + a re-apply; r88MACAddress_ stays the efuse
         * identity that start88's bootstrap re-verifies), net80211's TX/RX identity
         * (ic_myaddr), and the ABI readback (mac_). The driver's raw ifnet
         * keeps its locally-administered MAC (getHardwareAddress), so the
         * InterfaceNamer collision stays fixed. */
        const uint8_t *newMac = static_cast<const uint8_t *>(p1);
        memcpy(r88StationMAC_, newMac, 6);
        r88StationMACSet_ = true;
        memcpy(core_.sc_ic.ic_myaddr, newMac, 6);
        memcpy(mac_.bytes, newMac, 6);
        if (attached_ && present_ && core_.sc_ic.ic_state != IEEE80211_S_INIT)
            call->result = fromErrno(station88Hardware(core_.sc_ic.ic_state));
        else
            call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_STATUS) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        radioStatus(static_cast<struct rtl_radio_status *>(p1));
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_CHANNELS) == 0) {
        if (!p1 || !p2) { call->result = kIOReturnBadArgument; return; }
        radioChannels(static_cast<struct rtl_radio_chan *>(p1),
                      static_cast<uint32_t *>(p2));
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_SCAN_START) == 0) {
        call->result = radioScanStart(static_cast<const uint32_t *>(p1),
                                      static_cast<const uint32_t *>(p2));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_SCAN_COPY) == 0) {
        if (!p1 || !p2) { call->result = kIOReturnBadArgument; return; }
        radioScanCopy(static_cast<struct rtl_radio_bss *>(p1),
                      static_cast<uint32_t *>(p2));
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_JOIN) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        call->result = radioJoin(static_cast<struct rtl_radio_join *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_LEAVE) == 0) {
        call->result = radioLeave();
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_DATA_HOOK) == 0) {
        call->result = radioDataHook(reinterpret_cast<rtl_radio_rx_fn>(p1), p2);
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_TX) == 0) {
        call->result = radioTx(static_cast<mbuf_t>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_HOOK) == 0) {
        /* Raw AWDL-BSSID RX hook; frames are tapped in receive() before the
         * BSS admission filters. Hardware RX-filter coverage is a hardware
         * question (see the caveat in the tap comment). */
        radioAwdlHook_ = reinterpret_cast<rtl_radio_awdl_rx_fn>(p1);
        radioAwdlHookCtx_ = p1 ? p2 : nullptr;
        call->result = kIOReturnSuccess;
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_TX_80211) == 0) {
        call->result = radioTx80211(static_cast<const uint8_t *>(p1),
                                    static_cast<uint32_t *>(p2));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_SET_CHANNEL) == 0) {
        call->result = radioSetChannel(static_cast<const uint32_t *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_OFFCH) == 0) {
        call->result = radioAwdlOffch(static_cast<const uint32_t *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_RATE) == 0) {
        call->result = radioAwdlRate(static_cast<const uint32_t *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_TXSTAT) == 0) {
        if (!p1) { call->result = kIOReturnBadArgument; return; }
        call->result = radioAwdlTxStat(static_cast<struct rtl_radio_awdl_txstat *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_PORT) == 0) {
        call->result = radioAwdlPort(static_cast<const uint8_t *>(p1));
        return;
    }
    if (strcmp(fn, RTL_RADIO_FN_AWDL_RATE) == 0 ||
        strcmp(fn, RTL_RADIO_FN_AWDL_TXSTAT) == 0 ||
        strcmp(fn, RTL_RADIO_FN_SET_CHANNEL) == 0 ||
        strcmp(fn, RTL_RADIO_FN_AWDL_OFFCH) == 0 ||
        strcmp(fn, RTL_RADIO_FN_AWDL_AGG) == 0) {
        /* AwdlAgg needs host-driven BA agreements; the layer then sends
         * single frames. */
        call->result = kIOReturnUnsupported;
        return;
    }
}

/* ---- AWDL port 1 ----
 * Same registers as RTL8814Native's rtl8814native_radio_awdl_port on this
 * 8821C (AWDLTx.c): awdl0's MAC in REG_MACID1 (0x700), the AWDL BSSID in
 * REG_BSSID1 (0x708) and port 1 ad-hoc in MSR (0x102) bits 3:2, so the MAC
 * ACKs unicast frames addressed to awdl0; RCR (0x608) CBSSID_DATA (bit 6)
 * clear so data of other BSSIDs reaches the AWDL tap. The station code
 * only touches port 0's type bits but sets CBSSID_DATA on RUN, so
 * station88Hardware re-clears it while the port is on. Register state is
 * lost with the backend; start88 re-applies it. */
IOReturn RTWUSBController::radioAwdlPort(const uint8_t *mac) {
    if (!is88Family()) return kIOReturnUnsupported;
    if (mac) {
        memcpy(radioAwdlPortMac_, mac, 6);
        radioAwdlPort_ = true;
    } else {
        radioAwdlPort_ = false;
    }
    /* A torn-down backend takes it at the next start88. */
    if (!attached_ || !present_ || sleeping_ || usbError_ != kIOReturnSuccess ||
        core_.core_error || !running_ || !r88Station_.initialized)
        return kIOReturnSuccess;
    const int error = apply88AwdlPort(radioAwdlPort_);
    return error ? fromErrno(error) : kIOReturnSuccess;
}

int RTWUSBController::apply88AwdlPort(bool on) {
    static const uint8_t awdlBSSID[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    int e = 0;
    if (on) {
        for (unsigned i = 0; i < 6 && !e; ++i)
            e = r88Write(this, (uint16_t)(0x700 + i), 1, radioAwdlPortMac_[i]);
        for (unsigned i = 0; i < 6 && !e; ++i)
            e = r88Write(this, (uint16_t)(0x708 + i), 1, awdlBSSID[i]);
        if (e) return e;
    }
    uint32_t msr = 0;
    if ((e = r88Read(this, 0x102, 1, &msr))) return e;
    msr = (msr & ~0x0cu) | (on ? (0x01u << 2) : 0u);   /* 1 = ad-hoc, 0 = no link */
    if ((e = r88Write(this, 0x102, 1, msr))) return e;
    return awdl88Rcr();
}

int RTWUSBController::awdl88Rcr() {
    uint32_t rcr = 0;
    int e = r88Read(this, 0x608, 4, &rcr);
    if (e) return e;
    uint32_t want = rcr;
    /* RCR_AAP (bit 0) too, as on the RTL8814AU where AirDrop works (live RCR
     * 0xF40060CE, RTL8814Native Docs/AWDL_RTL8814_RX_ACK.md 2.1/2.4): AAP
     * passes all unicast to the host; port 1 only decides the hardware ACK.
     * Without it the 8821C dropped every unicast to awdl0 (efi-awdl
     * 2026-11-25, 5 GHz BSS: AF rx 1280, data rx 5, ping6 over awdl0 0/10).
     * Software drops non-AWDL unicast for other stations. */
    if (radioAwdlPort_) {
        want &= ~0x40u;
        want |= 0x01u;
    } else {
        want &= ~0x01u;                 /* station mode never sets AAP */
        if (r88Station_.state == RTW88_STATION_RUN)
            want |= 0x40u;              /* what rtw88_station_configure(RUN) sets */
    }
    return want == rcr ? 0 : r88Write(this, 0x608, 4, want);
}

void RTWUSBController::radioStatus(struct rtl_radio_status *out) {
    bzero(out, sizeof(*out));
    auto&ic = core_.sc_ic;
    switch (ic.ic_state) {
    case IEEE80211_S_INIT: out->state = RTL_RADIO_S_IDLE; break;
    case IEEE80211_S_SCAN: out->state = RTL_RADIO_S_SCAN; break;
    case IEEE80211_S_AUTH: case IEEE80211_S_ASSOC:
        out->state = RTL_RADIO_S_JOINING; break;
    case IEEE80211_S_RUN: out->state = RTL_RADIO_S_LINKED; break;
    default: break;
    }
    out->hook_attached = radioDataHook_ != nullptr;
    out->scanning = ic.ic_state == IEEE80211_S_SCAN ? 1 : 0;
    if (!ic.ic_bss) return;
    auto *n = ic.ic_bss;
    out->port_valid = n->ni_port_valid;
    out->rsn = (ic.ic_flags & IEEE80211_F_RSNON) != 0;
    memcpy(out->bssid, n->ni_bssid, 6);
    out->ssid_len = n->ni_esslen <= 32 ? n->ni_esslen : 0;
    memcpy(out->ssid, n->ni_essid, out->ssid_len);
    if (n->ni_chan && n->ni_chan != IEEE80211_CHAN_ANYC) {
        const uint32_t flags = n->ni_chan->ic_flags;
        out->channel = (uint8_t)ieee80211_chan2ieee(&ic, n->ni_chan);
        out->band = out->channel <= 14 ? RTL_RADIO_BAND_2G : RTL_RADIO_BAND_5G;
        if (flags & IEEE80211_CHAN_VHT80) out->bss_bw = RTL_RADIO_BW_80;
        else if (flags & IEEE80211_CHAN_HT40) out->bss_bw = RTL_RADIO_BW_40;
        else out->bss_bw = RTL_RADIO_BW_20;
        out->center = out->channel;     /* primary-centered approximation */
    }
    if (ic.ic_state == IEEE80211_S_RUN) {
        const uint64_t now = nowMS();
        out->rssi_dbm = rtw_signal_value(&signal_, n->ni_bssid, out->channel, now);
        out->nss = 1;                   /* RTL8821CU: single spatial stream */
    }
}

void RTWUSBController::radioChannels(struct rtl_radio_chan *out, uint32_t *count) {
    const uint32_t capacity = count ? *count : 0;
    uint32_t filled = 0;
    auto&ic = core_.sc_ic;
    for (uint16_t channel = 1; channel <= 165 && filled < capacity; ++channel) {
        if (channel > 14 && channel < 36) { channel = 35; continue; }
        if (channel > 64 && channel < 100) { channel = 99; continue; }
        if (channel > 116 && channel < 132) { channel = 131; continue; }
        if (channel > 140 && channel < 149) { channel = 148; continue; }
        const auto *ch = &ic.ic_channels[channel];
        if (!(ch->ic_flags & (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ)))
            continue;
        out[filled].channel = (uint8_t)channel;
        out[filled].band = channel <= 14 ? RTL_RADIO_BAND_2G : RTL_RADIO_BAND_5G;
        out[filled].passive = (ch->ic_flags & (IEEE80211_CHAN_PASSIVE | IEEE80211_CHAN_DFS)) != 0;
        out[filled].reserved = 0;
        ++filled;
    }
    if (count) *count = filled;
}

IOReturn RTWUSBController::radioScanStart(const uint32_t *channels, const uint32_t *count) {
    if (!attached_ || !present_ || sleeping_ || usbError_ != kIOReturnSuccess)
        return kIOReturnNotReady;
    if (rxRecovery_.pending) return kIOReturnBusy;
    /* The ABI's restricted channel list is a milestone-2 refinement; a full
     * plan scan is always legal per the ABI (restricted lists only narrow it). */
    (void)channels; (void)count;
    userRadioDisabled_ = false;
    if (!running_) return enableStation();
    /* S_RUN = associated and online: scans are legal (net80211 hops back to
     * the home channel per channel) — wedging them froze the native UI
     * (airportd's background scans all returned kIOReturnBusy).
     * But S_AUTH/S_ASSOC = the handshake in flight: a scan landing there
     * CANCELS the join and bounces the radio back to SCAN forever (the
     * auth/scan ping-pong — boot 11's "cannot connect"). Block scans during
     * the handshake exactly, let them through once RUN. */
    if (core_.sc_ic.ic_state >= IEEE80211_S_AUTH && core_.sc_ic.ic_state < IEEE80211_S_RUN)
        return kIOReturnBusy;
    /* S_RUN: do NOT begin a net80211 scan. ieee80211_begin_scan() runs
     * ieee80211_node_cleanup(ic_bss) (keys/port gone) and leaves RUN, so the
     * layer sees !LINKED and drops the link (efi-tahoe 2026-11-25: link_on,
     * airportd's post-join scan ~0.3 s later, link_off ~0.5 s after that,
     * every join). Accept the request instead: the layer's linked-scan path
     * waits ~2.5 s and then serves rtlRadioScanCopy from the node table,
     * which still holds the earlier scan results. Busy is no option (it
     * froze the native UI, see above). */
    if (core_.sc_ic.ic_state == IEEE80211_S_RUN)
        return kIOReturnSuccess;
    ieee80211_begin_scan(&core_.sc_ic.ic_if);
    return rtwn_io_error(&core_) ? kIOReturnIOError : kIOReturnSuccess;
}

void RTWUSBController::radioScanCopy(struct rtl_radio_bss *out, uint32_t *count) {
    const uint32_t capacity = count ? *count : 0;
    uint32_t filled = 0;
    auto&ic = core_.sc_ic;
    struct ieee80211_node *node = RB_MIN(ieee80211_tree, &ic.ic_tree);
    while (node && filled < capacity) {
        if (node->ni_esslen <= 32 && node->ni_chan && node->ni_chan != IEEE80211_CHAN_ANYC) {
            auto *r = &out[filled];
            bzero(r, sizeof(*r));
            memcpy(r->bssid, node->ni_bssid, 6);
            r->ssid_len = node->ni_esslen;
            memcpy(r->ssid, node->ni_essid, r->ssid_len);
            r->channel = (uint8_t)ieee80211_chan2ieee(&ic, node->ni_chan);
            r->band = r->channel <= 14 ? RTL_RADIO_BAND_2G : RTL_RADIO_BAND_5G;
            if (node->ni_rsnprotos & IEEE80211_PROTO_RSN) {
                r->security = (node->ni_rsnakms & IEEE80211_AKM_PSK) &&
                              (node->ni_rsnciphers & IEEE80211_CIPHER_CCMP) ? 3 : 2;
            }
            r->rssi_dbm = node->ni_rssi ? (int16_t)node->ni_rssi - 100 : 0;
            r->capinfo = node->ni_capinfo;
            r->intval = node->ni_intval;
            if (node->ni_rsnie && node->ni_rsnie[1] >= 1) {
                const uint16_t len = (uint16_t)(2 + node->ni_rsnie[1]);
                r->ies_len = len <= RTL_RADIO_MAX_IES ? len : RTL_RADIO_MAX_IES;
                memcpy(r->ies, node->ni_rsnie, r->ies_len);
            }
            ++filled;
        }
        node = RB_NEXT(ieee80211_tree, &ic.ic_tree, node);
    }
    if (count) *count = filled;
}

IOReturn RTWUSBController::radioJoin(struct rtl_radio_join *join) {
    if (!join || !join->ssid_len || join->ssid_len > 32)
        return kIOReturnBadArgument;
    if (join->is_sae) {
        /* The RTW88 backend joins WPA2-PSK/CCMP only (net80211 RSN). Wipe the
         * password the ABI promised to consume, then refuse. */
        bzero(join->sae_password, sizeof(join->sae_password));
        return kIOReturnUnsupported;
    }
    if (!attached_ || !present_ || sleeping_ || usbError_ != kIOReturnSuccess)
        return kIOReturnNotReady;
    userRadioDisabled_ = false;
    quiesce(true);
    if (join->has_pmk) {
        ieee80211_wpaparams parameters{};
        parameters.i_enabled = 1;
        parameters.i_protos = IEEE80211_WPA_PROTO_WPA2;
        parameters.i_akms = IEEE80211_WPA_AKM_PSK;
        parameters.i_ciphers = IEEE80211_WPA_CIPHER_CCMP;
        parameters.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        int error = ieee80211_ioctl_setwpaparms(&core_.sc_ic, &parameters);
        if (error && error != ENETRESET) return fromErrno(error);
        memcpy(core_.sc_ic.ic_psk, join->pmk, 32);
        core_.sc_ic.ic_flags |= IEEE80211_F_PSK;
    } else {
        core_.sc_ic.ic_flags &= ~IEEE80211_F_PSK;
    }
    core_.sc_ic.ic_des_esslen = join->ssid_len;
    memcpy(core_.sc_ic.ic_des_essid, join->ssid, join->ssid_len);
    joinRequested_ = true;
    IOReturn result = enableStation();
    if (result != kIOReturnSuccess) quiesce(true);
    return result;
}

IOReturn RTWUSBController::radioLeave() {
    userRadioDisabled_ = true;
    if (sleeping_) eraseProfile();
    else quiesce(true);
    return kIOReturnSuccess;
}

IOReturn RTWUSBController::radioDataHook(rtl_radio_rx_fn hook, void *ctx) {
    if (hook && radioDataHook_) return kIOReturnBusy;
    rtl_radio_rx_fn previous = radioDataHook_;
    radioDataHook_ = hook;
    radioDataHookCtx_ = hook ? ctx : nullptr;
    /* Owner pointer for the net80211 glue; cleared when the last hook leaves. */
    rtwRadioABIOwner = hook ? this :
        (rtwRadioABIOwner == this ? nullptr : rtwRadioABIOwner);
    (void)previous;
    radioLinkRefresh();
    return kIOReturnSuccess;
}

IOReturn RTWUSBController::radioTx(mbuf_t packet) {
    if (!packet) return kIOReturnBadArgument;
    if (stopping_ || !authorized()) { mbuf_freem(packet); return kIOReturnOutputDropped; }
    auto *queue = core_.sc_ic.ic_if.if_snd.queue;
    if (!queue) { mbuf_freem(packet); return kIOReturnOutputDropped; }
    if (!queue->lockEnqueue(packet)) {
        /* ABI consumers retry; keep the frame with the caller on stall. */
        return kIOReturnBusy;
    }
    rtwn_start(&core_.sc_ic.ic_if);
    return kIOReturnSuccess;
}

void RTWUSBController::radioLinkRefresh() {
    /* ABI rule: while the data hook owns RX, en2 reports its link inactive so
     * macOS does not route traffic through it behind the layer's back. */
    if (!netif_) return;
    if (radioDataHook_)
        setLinkStatus(kIONetworkLinkValid);
    else if (authorized())
        setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive);
    else
        setLinkStatus(kIONetworkLinkValid);
}

/* Diagnostics for AWDL TX (efi-awdl 2026-11-25: every PSF/MIF refused and
 * the layer's own error log had rotated out). Snapshot of the radio state at
 * the last refusal, published as RTWAwdlTxDiag. */
IOReturn RTWUSBController::radioTx80211(const uint8_t *frame, uint32_t *len) {
    const IOReturn r = radioTx80211Inner(frame, len);
    auto &d = radioTxDiag_;
    ++d.calls;
    if (r == kIOReturnSuccess) {
        ++d.ok;
    } else {
        ++d.fail;
        d.lastErr = (uint32_t)r;
        d.lastFailBits = (core_.core_error ? 1u : 0) | (!running_ ? 2u : 0) | (stopping_ ? 4u : 0) |
            (!present_ ? 8u : 0) | (sleeping_ ? 16u : 0) | (usbError_ != kIOReturnSuccess ? 32u : 0) |
            (r88Core_.firmware.last_error ? 64u : 0) | (!r88Station_.initialized ? 128u : 0) |
            (radioOffchState_ ? 256u : 0);
        d.lastSlotCh = radioOffchChannel_;
        const auto phy = rtw88_phy_radio_get_status(&r88PHY_);
        d.lastPhyCh = phy.primary_channel;
        d.lastPhyReady = (phy.error ? 4u : 0) | (phy.channel_ready ? 1u : 0) |
            (rtw88_phy_radio_ready(&r88PHY_) ? 2u : 0);
        d.lastBssCh = r88Channel_;
        d.lastRadioState = r88RadioState(this, r88Channel_);
        d.lastPending = ledger_.pending;
        d.lastLen = len ? *len : 0;
    }
    publishAwdlTxDiag(false);
    return r;
}

void RTWUSBController::publishAwdlTxDiag(bool force) {
    auto &d = radioTxDiag_;
    if (!force && d.calls > 8 && (d.calls & 31) != 0) return;
    char text[256];
    snprintf(text, sizeof(text),
             "calls %llu ok %llu fail %llu | last err 0x%x bits 0x%x slotCh %u phyCh %u phyReady %u "
             "bssCh %u radioState %u pending 0x%x len %u",
             d.calls, d.ok, d.fail, d.lastErr, d.lastFailBits, d.lastSlotCh, d.lastPhyCh,
             d.lastPhyReady, d.lastBssCh, d.lastRadioState, d.lastPending, d.lastLen);
    setProperty("RTWAwdlTxDiag", text);
}

IOReturn RTWUSBController::radioTx80211Inner(const uint8_t *frame, uint32_t *len) {
    /* ABI: one management frame, or one AWDL data frame (data or QoS data,
     * To/From DS 0, A3 = the AWDL BSSID), header and body, no FCS, on the
     * current operating channel. The radio supplies the sequence number. */
    if (!frame || !len) return kIOReturnBadArgument;
    const uint32_t length = *len;
    if (length < sizeof(ieee80211_frame) || length > 4096)
        return kIOReturnBadArgument;
    static const uint8_t awdlBSSID[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    const uint8_t type = frame[0] & IEEE80211_FC0_TYPE_MASK;
    const uint8_t direction = frame[1] & IEEE80211_FC1_DIR_MASK;
    const bool data = type == IEEE80211_FC0_TYPE_DATA;
    const bool qos = data && (frame[0] & IEEE80211_FC0_SUBTYPE_QOS) != 0;
    if (type == IEEE80211_FC0_TYPE_CTL) return kIOReturnBadArgument;
    if (data && (direction != IEEE80211_FC1_DIR_NODS ||
                 memcmp(frame + 16, awdlBSSID, 6)))
        return kIOReturnBadArgument;
    if (qos && length < sizeof(ieee80211_frame) + 2)
        return kIOReturnBadArgument;
    if (core_.core_error || !running_ || stopping_ || !present_ || sleeping_ ||
        usbError_ != kIOReturnSuccess || r88Core_.firmware.last_error ||
        !r88Station_.initialized)
        return kIOReturnNotReady;
    /* Gate like DrogaBox's rtl8814native_radio_tx_80211 (RTL8814Native
     * AWDLTx.c), where AirDrop works: no channel/readiness match at all; the
     * frame goes out on whatever channel the PHY is tuned to (the AWDL
     * channel during a slot, the BSS otherwise). It refuses only when TX is
     * impossible or an unassociated scan is away from the parked channel.
     * The fork's stricter r88RadioState/PHY-match gate refused EVERY PSF/MIF
     * (efi-awdl 2026-11-25: psf 0 mif 0 fail 268, mcc 219 ok). Infra data
     * stays held during a slot by the existing software hold (radioAwdlOffch);
     * these frames use the management queue directly. */
    if (core_.sc_ic.ic_state == IEEE80211_S_SCAN && !radioOffchState_)
        return kIOReturnBusy;
    const auto phy = rtw88_phy_radio_get_status(&r88PHY_);
    const uint8_t txChannel = !phy.error && phy.primary_channel ? (uint8_t)phy.primary_channel
                                                                : r88Channel_;
    if (!txChannel) return kIOReturnBusy;

    unsigned index = RTW_TRANSFER_SLOTS;
    IOInterruptState lock = IOSimpleLockLockDisableInterrupt(completionLock_);
    for (unsigned i = RXSlots; i < RTW_TRANSFER_SLOTS; ++i)
        if (!(ledger_.pending & (1U << i))) { index = i; break; }
    IOSimpleLockUnlockEnableInterrupt(completionLock_, lock);
    if (index == RTW_TRANSFER_SLOTS) return kIOReturnNoResources;

    uint32_t chunks = 0;
    mbuf_t packet = nullptr;
    if (mbuf_allocpacket(MBUF_DONTWAIT, length, &chunks, &packet) || !packet)
        return kIOReturnNoMemory;
    /* Sequence: the driver owns it for raw frames; keep it in one 802.11
     * sequence per Tx80211 call so retransmit logic stays coherent. */
    uint16_t sequence = (uint16_t)((++radioNextSeq_ << 4) & 0xfff0);
    const uint16_t sequenceLE = OSSwapHostToLittleInt16(sequence);
    if (mbuf_copyback(packet, 0, length, frame, MBUF_DONTWAIT) ||
        mbuf_copyback(packet, 22, 2, &sequenceLE, MBUF_DONTWAIT)) {
        mbuf_freem(packet);
        return kIOReturnNoMemory;
    }
    const bool multicast = (frame[4] & 1) != 0;
    rtw88_usb_tx_options options{};
    options.sequence = (uint16_t)(sequence >> 4);
    options.queue = data ? (qos ? (frame[24] & 15U) : 0) : 18;
    options.multicast = multicast;
    options.band_5ghz = txChannel > 14;
    /* Fixed rates: OFDM 6 Mb/s (mgmt) and 12 Mb/s (AWDL data) = indices 4/6
     * of the Linux-rtw88 rate table (0-3 CCK, 4-11 OFDM). */
    options.rate = data ? (radioAwdlRate_ ? radioAwdlRate_ : 6) : 4;
    options.rate_id = options.band_5ghz ? 7 : 8;
    options.firmware_rate = 0;
    options.disable_fallback = 1;
    options.disable_queue_sequence = 1;
    if (data && radioAwdlRate_) {
        /* Per-frame TX-status request (SMPS-style tag), counted in
         * rtlRadioAwdlTxStat by handle88C2H. */
        options.request_report = 1;
        options.report_tag = radioAwdlTag_;
    }
    uint8_t descriptor[48]{};
    if (rtw88_usb_make_tx_descriptor(family_, length, &options, descriptor,
                                     sizeof(descriptor)) != RTW88_USB_TX_OK) {
        mbuf_freem(packet);
        return kIOReturnBadArgument;
    }
    uint8_t pipe = 0;
    if (rtw88_mac_queue_endpoint(&r88MAC_.fifo, options.queue, &pipe) ||
        pipe >= endpoints_.num_bulk_out || !txPipes_[pipe]) {
        mbuf_freem(packet);
        return kIOReturnBadArgument;
    }
    size_t total = 48U + length;
    const uint16_t mps = txMPS_[pipe];
    if (mps != 64 && mps != 512 && mps != 1024) {
        mbuf_freem(packet);
        return kIOReturnBadArgument;
    }
    if (total % mps == 0) ++total;
    if (total > TXCapacity) {
        mbuf_freem(packet);
        return kIOReturnBadArgument;
    }
    auto *t = &transfers_[index];
    auto *bytes = static_cast<uint8_t *>(t->memory->getBytesNoCopy());
    bzero(bytes, total);
    memcpy(bytes, descriptor, 48);
    if (mbuf_copydata(packet, 0, length, bytes + 48)) {
        mbuf_freem(packet);
        return kIOReturnNoMemory;
    }
    mbuf_freem(packet);
    const int error = submit(index, txPipes_[pipe], (uint32_t)total);
    if (error) return error == ENOBUFS ? kIOReturnNoResources : fromErrno(error);
    return kIOReturnSuccess;
}

/* ---- AWDL milestone 3: parking, off-channel slots, rate, TX stats ---- */

IOReturn RTWUSBController::radioSetChannel(const uint32_t *channel) {
    /* ABI: parks the radio on one channel at 20 MHz while not associated.
     * Queued behind pending commands by the gate; later scans return to it
     * (see scanComplete). */
    if (!channel) return kIOReturnBadArgument;
    const uint8_t ch = (uint8_t)*channel;
    if (!ch || !permits88Channel(ch)) return kIOReturnBadArgument;
    if (!attached_ || !present_ || sleeping_ || usbError_ != kIOReturnSuccess ||
        core_.core_error)
        return kIOReturnNotReady;
    auto &ic = core_.sc_ic;
    if (ic.ic_state == IEEE80211_S_SCAN || ic.ic_state == IEEE80211_S_AUTH ||
        ic.ic_state == IEEE80211_S_ASSOC || ic.ic_state == IEEE80211_S_RUN)
        return kIOReturnBusy;
    /* While idle the RTW88 backend is torn down (board/PHY state released);
     * bring it back up exactly like the app's scan path does before any
     * register traffic. This also revives a user-disabled radio: an external
     * park command is an explicit radio use. */
    userRadioDisabled_ = false;
    const int recovery = recoverFamilyForControl();
    if (recovery) return fromErrno(recovery);
    if (core_.core_error || !r88PHY_.tables_loaded || !r88MAC_.mac_ready)
        return kIOReturnNotReady;
    const int error = set88Channel(ch, false);
    if (error) return fromErrno(error);
    radioIdleChannel_ = ch;
    return kIOReturnSuccess;
}

void RTWUSBController::radioAwdlNullFrame(uint8_t powerManagement) {
    /* One 24-byte null-data ToDS frame to the AP, sent on the BSS channel
     * through the ordinary data path. Fire-and-forget: the subsequent USB
     * register traffic of the channel switch gives the bulk-out a head
     * start; if the AP misses it, it buffers until the next PM clear. */
    auto &ic = core_.sc_ic;
    auto *n = ic.ic_bss;
    if (!n || ic.ic_state != IEEE80211_S_RUN || !r88Station_.initialized) return;
    uint32_t chunks = 0;
    mbuf_t packet = nullptr;
    if (mbuf_allocpacket(MBUF_DONTWAIT, 24, &chunks, &packet) || !packet) return;
    uint8_t frame[24]{};
    frame[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_NODATA;
    frame[1] = (uint8_t)(IEEE80211_FC1_DIR_TODS |
                         (powerManagement ? IEEE80211_FC1_PWR_MGT : 0));
    memcpy(frame + 4, n->ni_bssid, 6);
    memcpy(frame + 10, ic.ic_myaddr, 6);
    memcpy(frame + 16, n->ni_bssid, 6);
    const uint16_t sequence = (uint16_t)((++radioNextSeq_ << 4) & 0xfff0);
    frame[22] = (uint8_t)sequence;
    frame[23] = (uint8_t)(sequence >> 4);
    if (mbuf_copyback(packet, 0, sizeof(frame), frame, MBUF_DONTWAIT)) {
        mbuf_freem(packet);
        return;
    }
    ieee80211_ref_node(n);
    if (send88Frame(packet, n)) ieee80211_release_node(&ic, n);
}

IOReturn RTWUSBController::radioAwdlOffch(const uint32_t *channel) {
    /* ABI: while associated, move the radio to another channel for an AWDL
     * slot (at 20 MHz here; the same-block width refinement of the 8814
     * driver is a later step), or back to the BSS with channel 0. Leaving
     * sends a null frame with PM set and holds the data queues; returning
     * sends PM clear and resumes them. Bookkeeping stays on the BSS so
     * rtlRadioStatus keeps reporting it.
     *
     * A failed switch is recovered, not latched (efi-awdl 2026-11-25, BSS on
     * ch 1 + AWDL on 149: 4 s after syncing to an iPhone one switch failed,
     * core_error latched and every later SCAN/JOIN was NotReady until reboot).
     * On failure the radio goes back to the saved BSS operating state with a
     * calibrated set; only if that also fails is core_error latched. Plain
     * returns skip the calibration, like RTL8814Native's awdl_keep_txpwr. */
    if (!channel) return kIOReturnBadArgument;
    const uint32_t requested = *channel;
    const uint8_t ch = (uint8_t)requested;
    radioOffchLastErr_ = 0;
    radioOffchLastStep_ = 0;
    if (ch != requested && requested != 0) {
        radioOffchLastErr_ = EINVAL;
        radioOffchLastStep_ = 5;
        return kIOReturnBadArgument;
    }
    if (!attached_ || !present_ || sleeping_ || usbError_ != kIOReturnSuccess ||
        core_.core_error)
        return kIOReturnNoDevice;
    auto &ic = core_.sc_ic;
    if (!running_ || stopping_ || !r88Station_.initialized ||
        r88Core_.firmware.last_error)
        return kIOReturnNotReady;
    /* Linked-state first: while idle the RTW88 backend is torn down and a
     * channel check would misreport a legal AWDL channel as invalid. */
    if (rxRecovery_.pending) return kIOReturnBusy;
    if (ic.ic_state != IEEE80211_S_RUN || !ic.ic_bss) return kIOReturnBusy;
    if (ch && !permits88Channel(ch)) {
        radioOffchLastErr_ = EACCES;
        radioOffchLastStep_ = 6;
        return kIOReturnBadArgument;
    }

    const uint8_t home = r88Channel_;
    /* Back to the saved BSS state. calibrate: only when recovering. Returns
     * 0, or the errno that was latched. */
    auto restoreBSS = [&](bool calibrate, uint8_t from) -> int {
        int e = 0;
        if (r88Coex_ && (radioOffchSaved_.primary > 14) != (from > 14))
            e = coex88Notify(RTW88_CX_SWITCH_BAND, IEEE80211_S_RUN, radioOffchSaved_.primary);
        if (e) {                        /* coex is advisory: still retune */
            radioOffchLastErr_ = e;
            radioOffchLastStep_ = 3;
            ++radioOffchDiag_.coexFail;
        }
        int r = set88Operating(radioOffchSaved_, calibrate);
        if (r && !calibrate) r = set88Operating(radioOffchSaved_, true);
        r88Operating_ = radioOffchSaved_;
        r88Channel_ = radioOffchSaved_.primary;
        radioOffchState_ = 0; radioOffchChannel_ = 0;
        if (r) {
            radioOffchLastErr_ = r;
            radioOffchLastStep_ = 4;
            ++radioOffchDiag_.latched;
            core_.core_error = r;
            publishOffchDiag(true);
            return r;
        }
        radioAwdlNullFrame(0);          /* PM clear on the BSS channel */
        rtwn_start(&ic.ic_if);          /* flush the held data queues */
        return 0;
    };

    if (!ch || ch == home) {
        if (radioOffchState_) {
            const uint8_t from = radioOffchChannel_ ? radioOffchChannel_ : home;
            ++radioOffchDiag_.back;
            const int r = restoreBSS(false, from);
            publishOffchDiag(false);
            if (r) return fromErrno(r);
        }
        return kIOReturnSuccess;
    }
    const bool first = radioOffchState_ == 0;
    if (first) {
        radioOffchSaved_ = r88Operating_;
        radioAwdlNullFrame(1);          /* PM set while still on the BSS */
        radioOffchState_ = 1;
    }
    const uint8_t from = radioOffchChannel_ ? radioOffchChannel_ : home;
    ++radioOffchDiag_.out;
    int error = 0;
    if (r88Coex_ && (ch > 14) != (from > 14)) {
        const int notify = coex88Notify(RTW88_CX_SWITCH_BAND, IEEE80211_S_RUN, ch);
        if (notify) {
            radioOffchLastErr_ = notify;
            radioOffchLastStep_ = 1;
            ++radioOffchDiag_.coexFail;
            error = notify;
        }
    }
    if (!error) {
        error = set88Operating(rtw88_station_operating{ch, ch, 20, 0}, false);
        if (error) {
            radioOffchLastErr_ = error;
            radioOffchLastStep_ = 2;
        }
    }
    if (error) {
        /* Refuse this slot, but keep the link: back to the BSS. */
        ++radioOffchDiag_.outFail;
        const int lastErr = radioOffchLastErr_, lastStep = radioOffchLastStep_;
        const int r = restoreBSS(true, ch);
        if (!r) {
            radioOffchLastErr_ = lastErr;
            radioOffchLastStep_ = (uint8_t)lastStep;
            ++radioOffchDiag_.recovered;
        }
        publishOffchDiag(true);
        return fromErrno(r ? r : error);
    }
    /* Keep the ABI-visible radio state on the BSS while the PHY sits in the
     * AWDL slot; r88RadioState(BSS) is 0 meanwhile, so the data path stays
     * down even if something calls rtwn_start directly. */
    r88Operating_ = radioOffchSaved_;
    r88Channel_ = radioOffchSaved_.primary;
    radioOffchChannel_ = ch;            /* Tx80211 sends AWDL frames here */
    r88RX_.current_width = (uint8_t)(radioOffchSaved_.width_mhz == 80 ? 2 :
        radioOffchSaved_.width_mhz == 40 ? 1 : 0);
    publishOffchDiag(false);
    return kIOReturnSuccess;
}

void RTWUSBController::publishOffchDiag(bool force) {
    auto &d = radioOffchDiag_;
    if (!force && ((d.out + d.back) & 63) != 0) return;
    char text[200];
    snprintf(text, sizeof(text),
             "out %llu back %llu outFail %llu recovered %llu latched %llu coexFail %llu | "
             "last err %d step %u",
             d.out, d.back, d.outFail, d.recovered, d.latched, d.coexFail,
             radioOffchLastErr_, radioOffchLastStep_);
    setProperty("RTWAwdlOffchDiag", text);
    /* Failures also go to the kernel log: the ioreg copy is lost with the
     * reboot that usually follows a dead link. */
    if (force)
        IOLog("RTWAwdlOffch: %s r88Ch %u slotCh %u coreErr %d\n", text, r88Channel_,
              radioOffchChannel_, core_.core_error);
}

IOReturn RTWUSBController::radioAwdlRate(const uint32_t *rate) {
    /* ABI: TX descriptor rate index for unicast AWDL data frames; 0 = the
     * fixed 12 Mb/s. While set, frames ask the chip for a TX-status report
     * tagged radioAwdlTag_, counted in rtlRadioAwdlTxStat. */
    if (!rate) return kIOReturnBadArgument;
    const uint32_t value = *rate;
    if (!(value == 0 || (value >= 0x04 && value <= 0x0b) ||
          (value >= 0x0c && value <= 0x13)))
        return kIOReturnBadArgument;
    radioAwdlRate_ = value;
    /* Reserve the SMPS tag slot so the coex tag search never picks it. */
    r88SMPSTagRetire_[radioAwdlTag_ >> 2] = value ? UINT64_MAX : 0;
    return kIOReturnSuccess;
}

IOReturn RTWUSBController::radioAwdlTxStat(struct rtl_radio_awdl_txstat *out) {
    /* The 8821C TX-status report carries only the tag and an acked bit, so
     * the retry breakdown stays 0 until a per-retry C2H is identified. */
    if (!out) return kIOReturnBadArgument;
    bzero(out, sizeof(*out));
    out->clean = radioAwdlTxStat_.clean;
    out->retried = radioAwdlTxStat_.retried;
    out->retried2 = radioAwdlTxStat_.retried2;
    out->lost = radioAwdlTxStat_.lost;
    out->rate = radioAwdlRate_;
    out->reports = radioAwdlTxStat_.reports;
    return kIOReturnSuccess;
}
