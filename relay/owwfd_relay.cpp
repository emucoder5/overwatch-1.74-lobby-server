// owwfd_relay.cpp - PLAINTEXT transport relay at the ssl_stream boundary.
//
// Transport: wfd (0x298D6D8) -> byte-stream (wfd+0x80, vtable 0x298E2F8) -> ssl_stream at
// [bs+0x48] (vtable 0x298BED8). ssl_stream ABI: slot 0x10 = recv(this,dst,max,*out)->0 ok,
// slot 0x18 = send(this,buf,len,*out)->0 ok. bs.write hands PLAINTEXT to [bs+0x48].send.
//
// The byte-stream's send closure (0x21758a0) gates outbound on bs.state (slot1 [bs+0x20]) == 1.
// So: FORCE bs slot1 -> 1  => the client believes connected and writes PLAINTEXT (no TLS):
//   first a WebSocket upgrade "GET / HTTP/1.1 ... Upgrade: websocket", then BGS-over-WS frames.
// We swap [bs+0x48].send/recv to a byte-pipe: send -> our TCP socket to 127.0.0.1:21119 (RELAY_PORT, the
// Python BGS server in ow174/bnet, which does the WS upgrade + BGS), recv <- that socket. TLS never runs.
// Optional: with OW174_NETLOG=1 it also logs every address the game dials (see "network log" below), and
// with OW174_GCM_TRACE=1 it also logs every seal/open of a game-server packet (see "cipher trace").
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <intrin.h>
#pragma comment(lib,"ws2_32.lib")
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8; typedef int64_t i64;

static HINSTANCE g_module = nullptr;
static const u64 BS_VT=0x298E2F8ULL;          // byte-stream vtable
static const int SOCK_RECV_SLOT=2;            // [sockvt+0x10]
static const int SOCK_SEND_SLOT=3;            // [sockvt+0x18]
static const int VT_COPY=64;
static const u32 SRV_IP=0x7F000001;           // 127.0.0.1
static const u16 SRV_PORT=1119;
static const u16 RELAY_PORT=21119;            // always pipe the stripped plaintext here (our BGS WS server),
                                              // separate from the port the client dials (a hold-open stall)

static u64 g_base=0,g_imgHi=0; static FILE* g_log=nullptr; static CRITICAL_SECTION g_cs, g_mapCs;
static u64 g_bsVA=0, g_sockVtOrig=0; static u64* g_sockVtHeap=nullptr; static u64* g_bsVtHeap=nullptr;
static volatile LONG g_swaps=0,g_send=0,g_recv=0,g_stateCalls=0,g_wsaInit=0,g_relayErr=0;

// client-sock -> relay TCP socket (routed to the byte-stream's OWN target port)
struct Relay{ u64 cs; u16 port; SOCKET s; };
static Relay g_relays[64]; static int g_nRelays=0;

static void L(const char* f,...){char b[1600];va_list a;va_start(a,f);_vsnprintf(b,sizeof b-1,f,a);va_end(a);b[sizeof b-1]=0;EnterCriticalSection(&g_cs);if(g_log){fprintf(g_log,"[wfd] %s\n",b);fflush(g_log);}OutputDebugStringA("[wfd] ");OutputDebugStringA(b);OutputDebugStringA("\n");LeaveCriticalSection(&g_cs);}
static u64 rd64(void* a,u64 dv=0){u64 r;__try{r=*(volatile u64*)a;}__except(EXCEPTION_EXECUTE_HANDLER){return dv;}return r;}
static u32 rd32(void* a,u32 dv=0){u32 r;__try{r=*(volatile u32*)a;}__except(EXCEPTION_EXECUTE_HANDLER){return dv;}return r;}
static inline bool inImage(u64 p){return g_base<=p&&p<g_imgHi;}
static inline bool inHeap(u64 p){return p>=0x0000010000000000ULL&&p<0x00007FF000000000ULL&&(p&7)==0;}
static void hexlog(const char* tag,const u8* p,u64 n){ if(n>48)n=48; char h[200]; u64 m=0; for(u64 i=0;i<n;i++){int r=snprintf(h+m,sizeof h-m,"%02X ",p[i]); if(r<=0||m>sizeof h-4)break; m+=r;} L("  %s[%llu]: %s",tag,(unsigned long long)n,h); }

typedef int(*SockFn)(void* self, void* buf, u64 len, u64* out);

static int state_thunk(void* /*bs*/){ InterlockedIncrement(&g_stateCalls); return 1; }   // slot1: connected

// pre-register a client ssl_stream with the port IT targets (from [bs+0xa8]); connect lazily.
static void registerSock(u64 cs, u16 port){
    port=RELAY_PORT;  // ignore the client's target port; always pipe to our BGS server
    EnterCriticalSection(&g_mapCs);
    bool found=false;
    for(int i=0;i<g_nRelays;i++) if(g_relays[i].cs==cs){ found=true; break; }
    if(!found && g_nRelays<(int)(sizeof g_relays/sizeof g_relays[0])){
        g_relays[g_nRelays].cs=cs; g_relays[g_nRelays].port=port; g_relays[g_nRelays].s=INVALID_SOCKET; g_nRelays++;
    }
    LeaveCriticalSection(&g_mapCs);
}
// find the relay socket for a client ssl_stream; lazy-connect to 127.0.0.1:<its port>.
static SOCKET getRelay(u64 cs){
    SOCKET out=INVALID_SOCKET;
    EnterCriticalSection(&g_mapCs);
    for(int i=0;i<g_nRelays;i++) if(g_relays[i].cs==cs){
        if(g_relays[i].s==INVALID_SOCKET){
            if(!InterlockedCompareExchange(&g_wsaInit,1,0)){ WSADATA w; WSAStartup(MAKEWORD(2,2),&w); }
            SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            if(s!=INVALID_SOCKET){
                sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(g_relays[i].port); a.sin_addr.s_addr=htonl(SRV_IP);
                if(connect(s,(sockaddr*)&a,sizeof a)==0){ g_relays[i].s=s;
                    L("*** relay CONNECTED to 127.0.0.1:%u for clientSock=%016llX ***",g_relays[i].port,(unsigned long long)cs); }
                else { L("relay connect() 127.0.0.1:%u failed %d",g_relays[i].port,WSAGetLastError()); closesocket(s); }
            } else L("relay socket() failed %d",WSAGetLastError());
        }
        out=g_relays[i].s; break;
    }
    LeaveCriticalSection(&g_mapCs);
    return out;
}

// send: pipe outbound plaintext to the relay socket
static int send_thunk(void* self, void* buf, u64 len, u64* out){
    LONG n=InterlockedIncrement(&g_send);
    SOCKET r=getRelay((u64)self);
    if(n<=8||(n%500)==0){ L("SEND #%ld self=%016llX len=%llu relay=%lld",n,(unsigned long long)self,(unsigned long long)len,(long long)r);
        if(inHeap((u64)buf)||inImage((u64)buf)) hexlog("send",(const u8*)buf,len); }
    if(r!=INVALID_SOCKET && (inHeap((u64)buf)||inImage((u64)buf))){
        u64 off=0; int guard=0;
        while(off<len && guard++<10000){ int s=send(r,(const char*)buf+off,(int)(len-off),0);
            if(s>0){ off+=s; } else { int e=WSAGetLastError(); if(e==WSAEWOULDBLOCK){ Sleep(0); continue; } L("  send() err %d",e); InterlockedIncrement(&g_relayErr); break; } }
    }
    if(out)*out=len; return 0;                       // report fully sent; TLS never runs
}

// recv: pipe inbound plaintext from the relay socket (short block so request/response lands)
static int recv_thunk(void* self, void* dst, u64 maxlen, u64* out){
    LONG n=InterlockedIncrement(&g_recv);
    SOCKET r=getRelay((u64)self);
    if(r==INVALID_SOCKET){ if(out)*out=0; return 0; }
    fd_set rd; FD_ZERO(&rd); FD_SET(r,&rd); timeval tv; tv.tv_sec=0; tv.tv_usec=30000; // 30ms
    int sel=select(0,&rd,nullptr,nullptr,&tv);
    if(sel>0 && FD_ISSET(r,&rd)){
        int got=recv(r,(char*)dst,(int)maxlen,0);
        if(got>0){ if(out)*out=got; if(n<=8||(n%500)==0){ L("RECV #%ld self=%016llX got=%d",n,(unsigned long long)self,got); hexlog("recv",(const u8*)dst,got);} return 0; }
        if(got==0){ if(out)*out=0; if(n<=8)L("RECV #%ld server closed",n); return 0; }
        int e=WSAGetLastError(); if(e!=WSAEWOULDBLOCK){ if(n<=8)L("RECV #%ld recv err %d",n,e); }
    }
    if(out)*out=0; return 0;                          // no data yet
}

static void ensureVts(u64 svt){
    if(g_sockVtHeap) return;
    g_sockVtOrig=svt;
    g_sockVtHeap=(u64*)VirtualAlloc(NULL,VT_COPY*8,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    for(int i=0;i<VT_COPY;i++) g_sockVtHeap[i]=rd64((void*)(svt+i*8),0);
    g_sockVtHeap[SOCK_RECV_SLOT]=(u64)&recv_thunk;
    g_sockVtHeap[SOCK_SEND_SLOT]=(u64)&send_thunk;
    g_bsVtHeap=(u64*)VirtualAlloc(NULL,VT_COPY*8,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    for(int i=0;i<VT_COPY;i++) g_bsVtHeap[i]=rd64((void*)(g_bsVA+i*8),0);
    g_bsVtHeap[1]=(u64)&state_thunk;               // byte-stream slot1 (state) -> 1
    L("built vts: sockHeap=%p (from %llX rva %llX) bsHeap=%p",(void*)g_sockVtHeap,(unsigned long long)svt,(unsigned long long)(svt-g_base),(void*)g_bsVtHeap);
}

// ---- game-server crypto trace (opt-in: OW174_GCM_TRACE=1) ----
// The game's game-server wrappers (0x3FB2E0 open, 0x3FB740 seal) bottom out in two clean GCM leaves:
// 0x24D2500 VERIFY (recomputes the tag, compares it, returns al=1 on a match) and 0x24D2770 SEAL (computes
// the tag and writes it into the packet). Run 9eec49a9 proved the direction: the 0x24D2770 calls produced
// exactly the game's own outgoing tags (key +0xAE), and 0x24D2500 never fired while 9 of our replies came in,
// so the replies are dropped BEFORE the tag check. Both leaves take (a1 ctx, a2 pbAuthData, a3 cbAuthData,
// a4 pbData, a5 cbData, a6 pbNonce, a7 cbNonce, a8 pbTag, a9 cbTag) and return a bool in al.
// The game image cannot be re-protected (VirtualProtect fails with 87, run f7b869da), so this uses HARDWARE
// BREAKPOINTS: DR0 = verify, DR1 = seal on every game thread, and DR2 on each call's return address for the
// result. No byte of the game, no object and no vtable is touched. Off unless OW174_GCM_TRACE=1.
// A "GCM verify" line means a reply got past the game's header checks; its aad= is the header that did.
static const u64 GCM_OPEN_RVA=0x24D2500 /*verify*/, GCM_SEAL_RVA=0x24D2770 /*seal*/;
static volatile LONG g_gcmOpenN=0,g_gcmSealN=0; static bool g_gcmTrace=false; static volatile LONG g_gcmHooked=0;
// Armed only once the game dials the game server: breakpoints set at launch killed the game within ~2 s
// (its protection checks at startup), so nothing is set before Practice Range is clicked.
static volatile bool g_gcmGo=false;
static bool g_netlog=false;   // set by netInit() below

static int safeCopy(u8* dst,u64 src,int n){
    if(src<0x10000) return 0;
    __try{ memcpy(dst,(const void*)src,n); }__except(EXCEPTION_EXECUTE_HANDLER){ return 0; }
    return n;
}
static void hexLine(char* out,size_t cap,const u8* p,int n){
    size_t m=0; out[0]=0;
    for(int i=0;i<n&&m+4<cap;i++){ int r=snprintf(out+m,cap-m,"%02X",p[i]); if(r<=0)break; m+=r; }
}
struct GcmSnap{ bool ok[10]; u8 bytes[10][48]; };
static void gcmSnap(GcmSnap& s,const u64* a){
    for(int i=0;i<10;i++) s.ok[i]=safeCopy(s.bytes[i],a[i],48)==48;
}
static void gcmLog(bool open,LONG n,const u64* a,const GcmSnap& g,u64 ret,u64 caller,const char* stack){
    if(open ? n>4000 : n>3) return;             // every verify (they are the signal); the first seals only
    char aad[64]="?",nonce[32]="?",tag[32]="?";
    int la=(int)(a[2]<=22?a[2]:22);
    if(g.ok[1]) hexLine(aad,sizeof aad,g.bytes[1],la);
    if(g.ok[5]) hexLine(nonce,sizeof nonce,g.bytes[5],12);
    if(g.ok[7]) hexLine(tag,sizeof tag,g.bytes[7],12);
    L("GCM %s #%ld aad=%s len=%llu nonce=%s tag=%s caller=%s%llX",
      open?((ret&0xFF)?"verify PASS":"verify FAIL"):"seal",n,aad,(unsigned long long)a[4],nonce,tag,
      inImage(caller)?"rva ":"",(unsigned long long)(inImage(caller)?caller-g_base:caller));
    if(stack[0]) L("  stack (rva): %s",stack);
}
// One call in flight per thread (the leaves do not nest). Filled at entry, logged at return.
struct GcmCall{ bool armed, open; u64 a[10], ret; GcmSnap s; char stack[400]; };
static thread_local GcmCall t_gcm;
static void gcmStack(char* line,size_t cap){   // who calls it: the packet send / receive functions
    void* frames[16]; USHORT got=RtlCaptureStackBackTrace(2,16,frames,nullptr);
    size_t m=0; line[0]=0;
    for(USHORT i=0;i<got&&m+24<cap;i++){
        u64 f=(u64)frames[i];
        int r=inImage(f)?snprintf(line+m,cap-m,"%llX ",(unsigned long long)(f-g_base))
                        :snprintf(line+m,cap-m,"(%llX) ",(unsigned long long)f);
        if(r<=0)break; m+=r;
    }
}
static LONG CALLBACK gcmVeh(EXCEPTION_POINTERS* ep){
    if(ep->ExceptionRecord->ExceptionCode!=EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* c=ep->ContextRecord; u64 ip=c->Rip;
    u64 seal=g_base+GCM_SEAL_RVA, open=g_base+GCM_OPEN_RVA;
    GcmCall& g=t_gcm;
    if(ip==seal||ip==open){                        // entry: snapshot the args, break again on return
        if(!g.armed){
            u64 sp=c->Rsp;
            g.a[0]=c->Rcx; g.a[1]=c->Rdx; g.a[2]=c->R8; g.a[3]=c->R9;
            for(int i=4;i<10;i++) g.a[i]=rd64((void*)(sp+8+i*8),0);   // [rsp] = return, then 4 shadow slots
            gcmSnap(g.s,g.a);
            g.open=(ip==open); g.ret=rd64((void*)sp,0);
            LONG n=g.open?g_gcmOpenN:g_gcmSealN;
            if(n<3) gcmStack(g.stack,sizeof g.stack); else g.stack[0]=0;
            if(g.ret){ g.armed=true; c->Dr2=g.ret; c->Dr7=(c->Dr7&~0x0F000000ULL)|0x10; }   // L2, execute
        }
    }else if(g.armed&&ip==g.ret){                  // return: rax is SymCrypt's result
        g.armed=false; c->Dr2=0; c->Dr7&=~0x10ULL;
        if(g.open) gcmLog(true,InterlockedIncrement(&g_gcmOpenN),g.a,g.s,c->Rax,g.ret,g.stack);
        else       gcmLog(false,InterlockedIncrement(&g_gcmSealN),g.a,g.s,c->Rax,g.ret,g.stack);
    }else return EXCEPTION_CONTINUE_SEARCH;
    c->Dr6=0; c->EFlags|=0x10000;                  // RF: step over the execute breakpoint
    c->ContextFlags|=CONTEXT_DEBUG_REGISTERS;
    return EXCEPTION_CONTINUE_EXECUTION;
}
// Put DR0/DR1 on every thread of the game, including ones created later (called every second).
static int gcmArmThreads(){
    u64 seal=g_base+GCM_SEAL_RVA, open=g_base+GCM_OPEN_RVA; int armed=0;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); if(snap==INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te; te.dwSize=sizeof te; DWORD pid=GetCurrentProcessId(), me=GetCurrentThreadId();
    for(BOOL ok=Thread32First(snap,&te);ok;ok=Thread32Next(snap,&te)){
        if(te.th32OwnerProcessID!=pid||te.th32ThreadID==me) continue;
        HANDLE t=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
        if(!t) continue;
        if(SuspendThread(t)!=(DWORD)-1){
            alignas(16) CONTEXT c; memset(&c,0,sizeof c); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
            if(GetThreadContext(t,&c)&&(c.Dr0!=seal||c.Dr1!=open||(c.Dr7&5)!=5)){
                c.Dr0=seal; c.Dr1=open; c.Dr7=(c.Dr7&~0x00FF000FULL)|5;   // L0 L1, execute, len 1; DR2 left alone
                if(SetThreadContext(t,&c)) armed++;
            }
            ResumeThread(t);
        }
        CloseHandle(t);
    }
    CloseHandle(snap);
    return armed;
}
// The SymCrypt GcmEncrypt/GcmDecrypt prologue: REX push rbp, pushes, then `sub rsp, 0x110`. Both leaves
// share it. Checked before arming, so a different build -- or code not decrypted yet -- is left alone.
static const u8 GCM_PROLOGUE[11]={0x40,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x81,0xEC};
static void gcmTryHook(){
    if(!g_gcmTrace||!g_gcmGo) return;
    static int tries=0; tries++;
    if(!g_gcmHooked){
        u8 a[11],b[11];
        if(safeCopy(a,g_base+GCM_SEAL_RVA,11)!=11||memcmp(a,GCM_PROLOGUE,11)||
           safeCopy(b,g_base+GCM_OPEN_RVA,11)!=11||memcmp(b,GCM_PROLOGUE,11)){
            if(tries==1||tries%2500==0) L("GCM trace: waiting for GCM verify/seal to decrypt in memory");
            return;
        }
        if(!AddVectoredExceptionHandler(1,gcmVeh)){ L("GCM trace off: no exception handler"); g_gcmTrace=false; return; }
        g_gcmHooked=3;
        L("GCM trace: hardware breakpoints on GCM verify/seal (no game byte changed)");
    }
    if(tries%125!=1) return;                       // ~1 s: catch threads the game started since
    int n=gcmArmThreads();
    if(n) L("GCM trace: breakpoints set on %d more thread(s)",n);
}

static void scan(){
    gcmTryHook();
    SYSTEM_INFO si;GetSystemInfo(&si);u64 a=(u64)si.lpMinimumApplicationAddress,mx=(u64)si.lpMaximumApplicationAddress;MEMORY_BASIC_INFORMATION m;
    while(a<mx&&VirtualQuery((void*)a,&m,sizeof m)){
        u64 rb=(u64)m.BaseAddress,rs=m.RegionSize;
        if(m.State==MEM_COMMIT&&m.Type==MEM_PRIVATE&&inHeap(rb)&&(m.Protect&(PAGE_READWRITE|PAGE_EXECUTE_READWRITE))&&!(m.Protect&PAGE_GUARD)&&rs<=0x8000000){
            for(u64 p=rb;p+0xC0<=rb+rs;p+=8){
                u64 vt;__try{vt=*(volatile u64*)p;}__except(EXCEPTION_EXECUTE_HANDLER){continue;}
                if(vt!=g_bsVA) continue;                       // only unswapped byte-streams
                u64 bs=p; u64 sock=rd64((void*)(bs+0x48),0);
                if(!inHeap(sock)) continue;
                u64 svt=rd64((void*)sock,0);
                if(!inImage(svt)) continue;
                if(g_sockVtHeap && svt==(u64)g_sockVtHeap) continue;   // sock already swapped
                if(g_sockVtOrig && svt!=g_sockVtOrig){ continue; }     // different sock class - skip
                LONG sn=InterlockedIncrement(&g_swaps);
                u16 port=(u16)(rd32((void*)(bs+0xa8))&0xFFFF);
                char host[80]={0}; u64 hp=rd64((void*)(bs+0x80),0),hl=rd64((void*)(bs+0x88),0);
                const u8* hs=(inHeap(hp)?(const u8*)hp:(const u8*)(bs+0x80));
                for(u64 i=0;i<hl&&i<sizeof(host)-1;i++){u8 c=hs[i];host[i]=(c>=32&&c<127)?c:'.';}
                u32 st=rd32((void*)(bs+0x20));
                if(sn<=20 || port!=1119){     // ALWAYS log a non-1119 (e.g. lobby 3724) byte-stream
                    L("BYTE-STREAM bs=%016llX sock=%016llX sockVt(rva %llX) state=%u host='%s' port=%u swaps=%ld",
                      (unsigned long long)bs,(unsigned long long)sock,(unsigned long long)(svt-g_base),st,host,port,sn);
                }
                registerSock((u64)sock, port);
                ensureVts(svt);
                __try{ *(volatile u64*)sock=(u64)g_sockVtHeap; }__except(EXCEPTION_EXECUTE_HANDLER){}
                __try{ *(volatile u64*)bs=(u64)g_bsVtHeap; }__except(EXCEPTION_EXECUTE_HANDLER){}
            }
        }
        a=rb+rs;
    }
}
// ---- network log (opt-in: environment variable OW174_NETLOG=1, set by `py -m ow174 --experiment`) ----
// Logs every UDP/TCP socket the game opens and every address it binds, dials or sends to, so a game-server
// handoff experiment can tell "the game sent nothing" from "the game sent it somewhere else".
// The game hides its own pointers to Winsock, so the Winsock functions themselves are hooked: their first
// instructions move to a trampoline and are replaced by a jump to our logger, which then calls the
// trampoline. A function whose start we cannot move safely is left alone and named in the log.
#include "prologue.h"
typedef SOCKET (WSAAPI *socket_t)(int,int,int);
typedef SOCKET (WSAAPI *wsasocketw_t)(int,int,int,LPWSAPROTOCOL_INFOW,GROUP,DWORD);
typedef int (WSAAPI *bind_t)(SOCKET,const sockaddr*,int);
typedef int (WSAAPI *connect_t)(SOCKET,const sockaddr*,int);
typedef int (WSAAPI *wsaconnect_t)(SOCKET,const sockaddr*,int,LPWSABUF,LPWSABUF,LPQOS,LPQOS);
typedef int (WSAAPI *sendto_t)(SOCKET,const char*,int,int,const sockaddr*,int);
typedef int (WSAAPI *wsasendto_t)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,const sockaddr*,int,LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *recvfrom_t)(SOCKET,char*,int,int,sockaddr*,int*);
typedef int (WSAAPI *wsarecvfrom_t)(SOCKET,LPWSABUF,DWORD,LPDWORD,LPDWORD,sockaddr*,LPINT,LPWSAOVERLAPPED,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static socket_t o_socket=nullptr; static wsasocketw_t o_wsasocketw=nullptr; static bind_t o_bind=nullptr;
static connect_t o_connect=nullptr; static wsaconnect_t o_wsaconnect=nullptr;
static sendto_t o_sendto=nullptr; static wsasendto_t o_wsasendto=nullptr;
static recvfrom_t o_recvfrom=nullptr; static wsarecvfrom_t o_wsarecvfrom=nullptr;
static volatile LONG g_udpData=0;
static volatile LONG g_netPatched=0;   // g_netlog is declared with the cipher trace above

struct NetSeen{ char key[96]; LONG count; };
static NetSeen g_seen[256]; static int g_nSeen=0; static CRITICAL_SECTION g_netCs;

static void formatAddr(const sockaddr* to,int len,char* out,size_t n){
    out[0]=0;
    __try{
        if(!to||len<(int)sizeof(sockaddr)){ snprintf(out,n,"(no address)"); return; }
        if(to->sa_family==AF_INET&&len>=(int)sizeof(sockaddr_in)){
            const sockaddr_in* a=(const sockaddr_in*)to; const u8* b=(const u8*)&a->sin_addr;
            snprintf(out,n,"%u.%u.%u.%u:%u",b[0],b[1],b[2],b[3],ntohs(a->sin_port)); return;
        }
        if(to->sa_family==AF_INET6&&len>=(int)sizeof(sockaddr_in6)){
            const sockaddr_in6* a=(const sockaddr_in6*)to; const u8* b=(const u8*)&a->sin6_addr;
            snprintf(out,n,"[%02x%02x:%02x%02x:..:%02x%02x:%02x%02x]:%u",b[0],b[1],b[2],b[3],b[12],b[13],b[14],b[15],
                     ntohs(a->sin6_port)); return;
        }
        snprintf(out,n,"(family %u)",to->sa_family);
    }__except(EXCEPTION_EXECUTE_HANDLER){ snprintf(out,n,"(unreadable address)"); }
}

static const char* socketKind(SOCKET s){
    int type=0,len=sizeof type;
    if(getsockopt(s,SOL_SOCKET,SO_TYPE,(char*)&type,&len)!=0) return "?";
    return type==SOCK_DGRAM?"UDP":type==SOCK_STREAM?"TCP":"other";
}

// Log the first call per key, then every 1000th, so a busy socket does not flood the log.
static void netLog(const char* key,const char* detail){
    LONG count=0;
    EnterCriticalSection(&g_netCs);
    int i=0; for(;i<g_nSeen;i++) if(!strcmp(g_seen[i].key,key)) break;
    if(i==g_nSeen&&g_nSeen<(int)(sizeof g_seen/sizeof g_seen[0])){
        strncpy(g_seen[i].key,key,sizeof g_seen[i].key-1); g_seen[i].key[sizeof g_seen[i].key-1]=0; g_seen[i].count=0; g_nSeen++;
    }
    if(i<g_nSeen) count=++g_seen[i].count;
    LeaveCriticalSection(&g_netCs);
    if(count==1||count%1000==0) L("NET %s %s (call #%ld)",key,detail,count);
}
static void netNote(const char* fn,SOCKET s,const sockaddr* to,int len,long bytes){
    if(to&&len>=(int)sizeof(sockaddr_in)&&to->sa_family==AF_INET){   // the game dials our game server (3730+)
        u16 p=ntohs(((const sockaddr_in*)to)->sin_port); if(p>=3730&&p<3750) g_gcmGo=true;
    }
    char addr[64]; formatAddr(to,len,addr,sizeof addr);
    char key[96]; snprintf(key,sizeof key,"%s %s -> %s",fn,socketKind(s),addr);
    char detail[64]; snprintf(detail,sizeof detail,"socket=%llu bytes=%ld",(unsigned long long)s,bytes);
    netLog(key,detail);
}
static void netSocket(const char* fn,int af,int type,int proto,SOCKET s){
    char key[96]; snprintf(key,sizeof key,"%s af=%d %s proto=%d",fn,af,
                           type==SOCK_DGRAM?"UDP":type==SOCK_STREAM?"TCP":"other",proto);
    char detail[64]; snprintf(detail,sizeof detail,"-> socket=%llu",(unsigned long long)s);
    netLog(key,detail);
}

// The local port a socket is bound to, so a game-server receive can be tied to the socket that dialed 3730.
static u16 localPort(SOCKET s){
    sockaddr_in a; int l=sizeof a; memset(&a,0,sizeof a);
    if(getsockname(s,(sockaddr*)&a,&l)==0 && a.sin_family==AF_INET) return ntohs(a.sin_port);
    return 0;
}
// Log the receive side. Two distinct signals answer "is the game listening for a game-server reply?":
//   1. POLL  - the game CALLS recvfrom on a UDP socket (deduped: first + every 1000th). Proves it listens.
//   2. DATA  - the call RETURNS bytes (got>0). Proves a datagram (e.g. our reply) reached its recv path.
// got: >0 bytes received, 0 nothing this call (WOULDBLOCK / pending), -1 error/unknown.
static void netRecv(const char* fn,SOCKET s,int got,const sockaddr* from,int fromlen){
    const char* kind=socketKind(s); u16 lp=localPort(s);
    char key[96]; snprintf(key,sizeof key,"%s %s local=:%u socket=%llu",fn,kind,lp,(unsigned long long)s);
    netLog(key,"poll");                                    // signal 1: the game is reading this socket
    if(got>0){                                             // signal 2: real data landed (the important one)
        LONG d=InterlockedIncrement(&g_udpData);
        char addr[64]; formatAddr(from,fromlen,addr,sizeof addr);
        if(d<=64||(d%1000)==0) L("RECVDATA %s %s local=:%u from %s got=%d socket=%llu",
                                 fn,kind,lp,addr,got,(unsigned long long)s);
    }
}

static SOCKET WSAAPI hk_socket(int af,int type,int proto){
    SOCKET s=o_socket(af,type,proto); netSocket("socket",af,type,proto,s); return s;
}
static SOCKET WSAAPI hk_wsasocketw(int af,int type,int proto,LPWSAPROTOCOL_INFOW info,GROUP g,DWORD flags){
    SOCKET s=o_wsasocketw(af,type,proto,info,g,flags); netSocket("WSASocketW",af,type,proto,s); return s;
}
static int WSAAPI hk_bind(SOCKET s,const sockaddr* at,int len){
    netNote("bind",s,at,len,0); return o_bind(s,at,len);
}
static int WSAAPI hk_connect(SOCKET s,const sockaddr* to,int len){
    netNote("connect",s,to,len,0); return o_connect(s,to,len);
}
static int WSAAPI hk_wsaconnect(SOCKET s,const sockaddr* to,int len,LPWSABUF a,LPWSABUF b,LPQOS c,LPQOS d){
    netNote("WSAConnect",s,to,len,0); return o_wsaconnect(s,to,len,a,b,c,d);
}
static int WSAAPI hk_sendto(SOCKET s,const char* buf,int n,int flags,const sockaddr* to,int len){
    if(to) netNote("sendto",s,to,len,n);
    return o_sendto(s,buf,n,flags,to,len);
}
static int WSAAPI hk_wsasendto(SOCKET s,LPWSABUF bufs,DWORD count,LPDWORD sent,DWORD flags,const sockaddr* to,int len,
                               LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE done){
    if(to){ long total=0; __try{ for(DWORD i=0;i<count;i++) total+=(long)bufs[i].len; }__except(EXCEPTION_EXECUTE_HANDLER){}
            netNote("WSASendTo",s,to,len,total); }
    return o_wsasendto(s,bufs,count,sent,flags,to,len,ov,done);
}
static int WSAAPI hk_recvfrom(SOCKET s,char* buf,int len,int flags,sockaddr* from,int* fromlen){
    int r=o_recvfrom(s,buf,len,flags,from,fromlen);
    netRecv("recvfrom",s,r,from,fromlen?*fromlen:0);
    return r;
}
static int WSAAPI hk_wsarecvfrom(SOCKET s,LPWSABUF bufs,DWORD count,LPDWORD recvd,LPDWORD flags,sockaddr* from,
                                 LPINT fromlen,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cr){
    int r=o_wsarecvfrom(s,bufs,count,recvd,flags,from,fromlen,ov,cr);
    // Immediate completion gives bytes in *recvd; overlapped returns pending and completes later, so log the
    // poll either way and the byte count when we have it now.
    netRecv("WSARecvFrom",s,(r==0&&recvd)?(int)*recvd:0,from,fromlen?*fromlen:0);
    return r;
}

struct NetHook{ const char* name; void** original; void* hook; };
static NetHook g_hooks[]={
    {"socket",(void**)&o_socket,(void*)&hk_socket},
    {"WSASocketW",(void**)&o_wsasocketw,(void*)&hk_wsasocketw},
    {"bind",(void**)&o_bind,(void*)&hk_bind},
    {"connect",(void**)&o_connect,(void*)&hk_connect},
    {"WSAConnect",(void**)&o_wsaconnect,(void*)&hk_wsaconnect},
    {"sendto",(void**)&o_sendto,(void*)&hk_sendto},
    {"WSASendTo",(void**)&o_wsasendto,(void*)&hk_wsasendto},
    {"recvfrom",(void**)&o_recvfrom,(void*)&hk_recvfrom},
    {"WSARecvFrom",(void**)&o_wsarecvfrom,(void*)&hk_wsarecvfrom},
};
static const int N_HOOKS=(int)(sizeof g_hooks/sizeof g_hooks[0]);

static const int JUMP_LEN=12;   // mov rax, imm64 (10 bytes) + jmp rax (2); rax is free at a function entry
static void writeJump(u8* at,u64 target){ at[0]=0x48; at[1]=0xB8; memcpy(at+2,&target,8); at[10]=0xFF; at[11]=0xE0; }

// Hook one function: copy its first whole instructions (>= 12 bytes) to a trampoline that jumps back,
// then overwrite them with a jump to the hook. The trampoline becomes the "original" the hook calls.
static bool inlineHook(u8* fn,void* hook,void** original,u8* trampoline,const char* name){
    u8 head[32]; memset(head,0,sizeof head);
    __try{ memcpy(head,fn,24); }__except(EXCEPTION_EXECUTE_HANDLER){ L("NET hook %s: unreadable",name); return false; }
    int n=prologueLength(head,JUMP_LEN);
    if(n<0||n>24){
        L("NET hook %s: skipped, unsupported start %02X %02X %02X %02X %02X %02X %02X %02X",name,
          head[0],head[1],head[2],head[3],head[4],head[5],head[6],head[7]);
        return false;
    }
    memcpy(trampoline,head,n);
    trampoline[n]=0xFF; trampoline[n+1]=0x25; memset(trampoline+n+2,0,4);   // jmp [rip+0]
    u64 back=(u64)(fn+n); memcpy(trampoline+n+6,&back,8);
    *original=trampoline;
    DWORD old;
    if(!VirtualProtect(fn,n,PAGE_EXECUTE_READWRITE,&old)){ L("NET hook %s: VirtualProtect failed %lu",name,GetLastError()); return false; }
    u8 patch[32]; writeJump(patch,(u64)hook); for(int i=JUMP_LEN;i<n;i++) patch[i]=0x90;
    memcpy(fn,patch,n);
    VirtualProtect(fn,n,old,&old);
    FlushInstructionCache(GetCurrentProcess(),fn,n);
    L("NET hook %s: on (%d bytes moved)",name,n);
    return true;
}

// A function that starts with a jump (a forwarding stub, or another program's hook) is hooked where the
// jump lands instead.
static u8* followJumps(u8* fn){
    for(int hop=0;hop<4;hop++){
        u8* p=fn; u8* next=nullptr;
        __try{
            if(p[0]==0xF3&&p[1]==0x0F&&p[2]==0x1E&&p[3]==0xFA) p+=4;                   // endbr64
            if(p[0]==0xE9) next=p+5+*(int32_t*)(p+1);                                 // jmp rel32
            else if(p[0]==0xFF&&p[1]==0x25) next=*(u8**)(p+6+*(int32_t*)(p+2));       // jmp [rip+x]
        }__except(EXCEPTION_EXECUTE_HANDLER){ next=nullptr; }
        if(!next) break;
        fn=next;
    }
    return fn;
}

static void netInit(){
    wchar_t flag[8]={0};
    DWORD n=GetEnvironmentVariableW(L"OW174_NETLOG",flag,8);
    g_netlog=(n>0&&n<8&&flag[0]==L'1');
    if(!g_netlog) return;
    InitializeCriticalSection(&g_netCs);
    HMODULE ws=GetModuleHandleW(L"ws2_32.dll"); if(!ws) ws=LoadLibraryW(L"ws2_32.dll");
    if(!ws){ L("NET log off: ws2_32.dll not loadable"); g_netlog=false; return; }
    u8* pool=(u8*)VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!pool){ L("NET log off: no trampoline memory"); g_netlog=false; return; }
    for(int h=0;h<N_HOOKS;h++){
        u8* fn=(u8*)GetProcAddress(ws,g_hooks[h].name);
        if(!fn){ L("NET hook %s: not exported",g_hooks[h].name); continue; }
        fn=followJumps(fn);
        if(inlineHook(fn,g_hooks[h].hook,g_hooks[h].original,pool+h*64,g_hooks[h].name)) InterlockedIncrement(&g_netPatched);
    }
    L("NET log on: %ld of %d Winsock functions hooked",g_netPatched,N_HOOKS);
}

static DWORD WINAPI worker(LPVOID){
    InitializeCriticalSection(&g_cs);InitializeCriticalSection(&g_mapCs);
    wchar_t modulePath[32768] = {};
    DWORD pathLength = GetModuleFileNameW(g_module, modulePath, 32768);
    if (pathLength > 0 && pathLength < 32768) {
        std::wstring directory(modulePath, pathLength);
        const auto slash = directory.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            directory = directory.substr(0, slash) + L"\\log";
            CreateDirectoryW(directory.c_str(), nullptr);
            const std::wstring logPath = directory + L"\\wfd.log";
            g_log = _wfopen(logPath.c_str(), L"a");
        }
    }
    g_base=(u64)GetModuleHandleW(L"Overwatch.exe");if(!g_base)g_base=(u64)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)g_base;IMAGE_NT_HEADERS* nt=(IMAGE_NT_HEADERS*)(g_base+dos->e_lfanew);g_imgHi=g_base+nt->OptionalHeader.SizeOfImage;
    g_bsVA=g_base+BS_VT;
    L("==== owwfd_relay (plaintext pipe -> 127.0.0.1:%u) base=%016llX bsVt=%016llX ====",RELAY_PORT,(unsigned long long)g_base,(unsigned long long)g_bsVA);
    netInit();
    { wchar_t f[8]={0}; DWORD n=GetEnvironmentVariableW(L"OW174_GCM_TRACE",f,8); g_gcmTrace=(n>0&&n<8&&f[0]==L'1'); }
    if(g_gcmTrace) L("GCM trace requested (OW174_GCM_TRACE=1): will set hardware breakpoints on GCM verify/seal when the game dials the game server");
    for(int loop=0;;loop++){
        scan();
        if((loop%80)==0)L("[poll] loop=%d swaps=%ld send=%ld recv=%ld stateCalls=%ld relays=%d err=%ld net=%ld gcm=%ld/%ld/%ld",loop,g_swaps,g_send,g_recv,g_stateCalls,g_nRelays,g_relayErr,g_netPatched,g_gcmHooked,g_gcmSealN,g_gcmOpenN);
        Sleep(8);
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){g_module=h;DisableThreadLibraryCalls(h);HANDLE t=CreateThread(nullptr,0,worker,nullptr,0,nullptr);if(t)CloseHandle(t);}return TRUE;}
