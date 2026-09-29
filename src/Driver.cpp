#include <ntddk.h>
#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>

DEFINE_GUID(FT_SUBLAYER,    0x1e61a5c1, 0x90be, 0x4c00, 0x76, 0x25, 0x88, 0x82, 0xea, 0x38, 0xdd, 0x89);
DEFINE_GUID(FT_CALLOUT_IN,  0xbc52e90a, 0x4878, 0xde4d, 0xc5, 0x4d, 0x02, 0x6e, 0x6d, 0x50, 0xe4, 0x12);
DEFINE_GUID(FT_CALLOUT_OUT, 0x5b54e759, 0xa5e7, 0xfde4, 0x9f, 0x63, 0x85, 0xe4, 0xcc, 0x25, 0xe4, 0x59);

static HANDLE gEngine;
static PDEVICE_OBJECT gDevice;
static UINT32 gIdIn, gIdOut;

static KSPIN_LOCK gLock;
static BOOLEAN gDone, gHaveLocal, gHaveGwMac, gHaveGwIp;
static UCHAR gLocalMac[6], gLocalIp[4], gGwMac[6], gGwIp[4];

static BOOLEAN UnicastMac(const UCHAR* m) { return (m[0] & 1) == 0; }

static BOOLEAN PublicIp(const UCHAR* a)
{
    if (a[0] == 0 || a[0] == 127 || a[0] >= 224) return FALSE;
    if (a[0] == 10) return FALSE;
    if (a[0] == 172 && a[1] >= 16 && a[1] <= 31) return FALSE;
    if (a[0] == 192 && a[1] == 168) return FALSE;
    if (a[0] == 169 && a[1] == 254) return FALSE;
    return TRUE;
}

static void Inspect(const NET_BUFFER_LIST* nbl, BOOLEAN outbound)
{
    if (gDone || !nbl) return;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)nbl);
    if (!nb) return;

    UCHAR b[42];
    UCHAR* p = (UCHAR*)NdisGetDataBuffer(nb, 14, b, 1, 0);
    if (!p) return;
    USHORT eth = (USHORT)((p[12] << 8) | p[13]);

    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    
    if (eth == 0x0800)
    {
        UCHAR* q = (UCHAR*)NdisGetDataBuffer(nb, 34, b, 1, 0);
        if (q)
        {
            UCHAR* lm  = outbound ? q + 6  : q + 0;
            UCHAR* gm  = outbound ? q + 0  : q + 6;
            UCHAR* lip = outbound ? q + 26 : q + 30;
            UCHAR* rip = outbound ? q + 30 : q + 26;
            if (!gHaveLocal && UnicastMac(lm) && lip[0] != 0)
            {
                RtlCopyMemory(gLocalMac, lm, 6); RtlCopyMemory(gLocalIp, lip, 4); gHaveLocal = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FilterTap: got LOCAL\n");
            }
            if (!gHaveGwMac && UnicastMac(gm) && PublicIp(rip))
            {
                RtlCopyMemory(gGwMac, gm, 6); gHaveGwMac = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FilterTap: got GW MAC\n");
            }
        }
    }
    else if (eth == 0x0806)
    {
        UCHAR* a = (UCHAR*)NdisGetDataBuffer(nb, 42, b, 1, 0);
        if (a && gHaveGwMac && !gHaveGwIp)
        {
            if (RtlEqualMemory(a + 22, gGwMac, 6))      { RtlCopyMemory(gGwIp, a + 28, 4); gHaveGwIp = TRUE; }
            else if (RtlEqualMemory(a + 32, gGwMac, 6)) { RtlCopyMemory(gGwIp, a + 38, 4); gHaveGwIp = TRUE; }
            if (gHaveGwIp) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FilterTap: got GW IP\n");
        }
    }
    
    //Not actively used just POC
    if ( eth == 0x0800 && outbound )
    {
        UCHAR  dbuf[320];
        ULONG  avail = NET_BUFFER_DATA_LENGTH( nb );
        ULONG  want = avail < sizeof( dbuf ) ? avail : sizeof( dbuf );
        if ( want < 14 + 20 + 8 + 12 ) goto dns_done;

        UCHAR* pkt = (UCHAR*)NdisGetDataBuffer( nb, want, dbuf, 1, 0 );
        if ( !pkt ) goto dns_done;

        UCHAR* iph = pkt + 14;
        ULONG  ihl = ( iph[0] & 0x0F ) * 4;
        UCHAR  prot = iph[9];

        if ( prot == 17 && ihl >= 20 && 14 + ihl + 8 + 12 <= want )
        {
            UCHAR* udp = iph + ihl;
            USHORT dport = (USHORT)( ( udp[2] << 8 ) | udp[3] );

            if ( dport == 53 )
            {
                UCHAR* dns = udp + 8;
                USHORT flags = (USHORT)( ( dns[2] << 8 ) | dns[3] );
                USHORT qd = (USHORT)( ( dns[4] << 8 ) | dns[5] );

                if ( ( flags & 0x8000 ) == 0 && qd >= 1 )
                {
                    UCHAR* name = dns + 12;
                    UCHAR* end = pkt + want;
                    CHAR   out[256];
                    ULONG  oi = 0;

                    while ( name < end && *name && oi + 1 < sizeof( out ) )
                    {
                        UCHAR len = *name++;
                        if ( len & 0xC0 ) break;
                        if ( len == 0 || name + len > end ) break;
                        if ( oi ) out[oi++] = '.';
                        for ( UCHAR i = 0; i < len && oi + 1 < sizeof( out ); i++ )
                        {
                            CHAR c = (CHAR)name[i];
                            out[oi++] = ( c >= 0x20 && c < 0x7F ) ? c : '?';
                        }
                        name += len;
                    }
                    out[oi] = 0;

                    if ( oi )
                    {
                        USHORT qtype = 0;
                        if ( name < end && *name == 0 && name + 5 <= end )
                            qtype = (USHORT)( ( name[1] << 8 ) | name[2] );

                        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                            "FilterTap DNS Q type=%u %s\n", qtype, out );
                    }
                }
            }
        }
    dns_done:;
    }

    if (gHaveLocal && gHaveGwMac && !gDone)
    {
        gDone = TRUE;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "FilterTap LOCAL   %02X:%02X:%02X:%02X:%02X:%02X  %u.%u.%u.%u\n",
            gLocalMac[0], gLocalMac[1], gLocalMac[2], gLocalMac[3], gLocalMac[4], gLocalMac[5],
            gLocalIp[0], gLocalIp[1], gLocalIp[2], gLocalIp[3]);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "FilterTap ROUTER  %02X:%02X:%02X:%02X:%02X:%02X\n",
            gGwMac[0], gGwMac[1], gGwMac[2], gGwMac[3], gGwMac[4], gGwMac[5]);
    }

    KeReleaseSpinLock(&gLock, irql);
}

static void NTAPI ClassifyIn(const FWPS_INCOMING_VALUES0* in, const FWPS_INCOMING_METADATA_VALUES0* m,
    void* layerData, const void* ctx, const FWPS_FILTER1* f, UINT64 flow, FWPS_CLASSIFY_OUT0* out)
{
    UNREFERENCED_PARAMETER(in); UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(flow);
    Inspect((const NET_BUFFER_LIST*)layerData, FALSE);
    out->actionType = FWP_ACTION_CONTINUE;
}

static void NTAPI ClassifyOut(const FWPS_INCOMING_VALUES0* in, const FWPS_INCOMING_METADATA_VALUES0* m,
    void* layerData, const void* ctx, const FWPS_FILTER1* f, UINT64 flow, FWPS_CLASSIFY_OUT0* out)
{
    UNREFERENCED_PARAMETER(in); UNREFERENCED_PARAMETER(m); UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(f); UNREFERENCED_PARAMETER(flow);
    Inspect((const NET_BUFFER_LIST*)layerData, TRUE);
    out->actionType = FWP_ACTION_CONTINUE;
}

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE t, const GUID* k, FWPS_FILTER1* f)
{
    UNREFERENCED_PARAMETER(t); UNREFERENCED_PARAMETER(k); UNREFERENCED_PARAMETER(f);
    return STATUS_SUCCESS;
}

static NTSTATUS AddFilter(const GUID* layer, const GUID* callout, const wchar_t* name)
{
    FWPM_FILTER0 fl = { 0 };
    fl.layerKey = *layer;
    fl.subLayerKey = FT_SUBLAYER;
    fl.displayData.name = (wchar_t*)name;
    fl.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    fl.action.calloutKey = *callout;
    fl.weight.type = FWP_UINT8;
    fl.weight.uint8 = 15;
    return FwpmFilterAdd0(gEngine, &fl, NULL, NULL);
}

static NTSTATUS Register(PDEVICE_OBJECT dev, const GUID* key, FWPS_CALLOUT_CLASSIFY_FN1 fn,
    const GUID* layer, UINT32* id, const wchar_t* name)
{
    FWPS_CALLOUT1 c = { 0 };
    c.calloutKey = *key;
    c.classifyFn = fn;
    c.notifyFn = Notify;
    NTSTATUS s = FwpsCalloutRegister1(dev, &c, id);
    if (!NT_SUCCESS(s)) return s;

    FWPM_CALLOUT0 mc = { 0 };
    mc.calloutKey = *key;
    mc.displayData.name = (wchar_t*)name;
    mc.applicableLayer = *layer;
    return FwpmCalloutAdd0(gEngine, &mc, NULL, NULL);
}

static void Cleanup()
{
    if (gEngine) { FwpmEngineClose0(gEngine); gEngine = NULL; }
    if (gIdIn)  { FwpsCalloutUnregisterById0(gIdIn);  gIdIn = 0; }
    if (gIdOut) { FwpsCalloutUnregisterById0(gIdOut); gIdOut = 0; }
    if (gDevice) { IoDeleteDevice(gDevice); gDevice = NULL; }
}

static void NTAPI Unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    Cleanup();
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "LOADED" );

    UNREFERENCED_PARAMETER(reg);
    drv->DriverUnload = Unload;
    KeInitializeSpinLock(&gLock);

    NTSTATUS s = IoCreateDevice(drv, 0, NULL, FILE_DEVICE_NETWORK, 0, FALSE, &gDevice);
    if (!NT_SUCCESS(s)) return s;

    FWPM_SESSION0 sess = { 0 };
    sess.flags = FWPM_SESSION_FLAG_DYNAMIC;
    s = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &sess, &gEngine);
    if (!NT_SUCCESS(s)) { Cleanup(); return s; }

    s = FwpmTransactionBegin0(gEngine, 0);
    if (!NT_SUCCESS(s)) { Cleanup(); return s; }

    FWPM_SUBLAYER0 sub = { 0 };
    sub.subLayerKey = FT_SUBLAYER;
    sub.displayData.name = (wchar_t*)L"FilterTap";
    sub.weight = 0xffff;

    s = FwpmSubLayerAdd0(gEngine, &sub, NULL);
    if (NT_SUCCESS(s)) s = Register(gDevice, &FT_CALLOUT_IN, ClassifyIn,
        &FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET, &gIdIn, L"FilterTap IN");
    if (NT_SUCCESS(s)) s = Register(gDevice, &FT_CALLOUT_OUT, ClassifyOut,
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET, &gIdOut, L"FilterTap OUT");
    if (NT_SUCCESS(s)) s = AddFilter(&FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET, &FT_CALLOUT_IN, L"FilterTap IN");
    if (NT_SUCCESS(s)) s = AddFilter(&FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET, &FT_CALLOUT_OUT, L"FilterTap OUT");

    if (!NT_SUCCESS(s)) { FwpmTransactionAbort0(gEngine); Cleanup(); return s; }

    s = FwpmTransactionCommit0(gEngine);
    if (!NT_SUCCESS(s)) { Cleanup(); return s; }

    return STATUS_SUCCESS;
}