// prologue.h - how many whole instructions at the start of a function cover at least N bytes (x64).
//
// Used to move the first instructions of a Winsock function into a trampoline before overwriting them
// with a jump. Only instructions that are safe to run from another address are accepted: no relative
// jumps or calls, and no RIP-relative memory operands. Anything else makes the hook give up (returns
// -1) instead of guessing, so an unexpected prologue means "not hooked", never a crash.
#pragma once
#include <cstdint>

// Length of the ModRM operand (ModRM byte, optional SIB, displacement), or -1 for RIP-relative.
static int modrmLength(const uint8_t* p){
    uint8_t modrm=p[0]; int mod=modrm>>6, rm=modrm&7, len=1;
    if(mod==3) return 1;
    if(rm==4){                                   // SIB byte follows
        uint8_t sib=p[1]; len++;
        if(mod==0&&(sib&7)==5) len+=4;           // no base register: disp32
    }else if(mod==0&&rm==5){
        return -1;                               // RIP-relative: would point elsewhere once moved
    }
    if(mod==1) len+=1; else if(mod==2) len+=4;
    return len;
}

// Length of one instruction, or -1 when it is not one we accept.
static int instructionLength(const uint8_t* p){
    if(p[0]==0xF3&&p[1]==0x0F&&p[2]==0x1E&&p[3]==0xFA) return 4;   // endbr64
    int len=0; bool wide=false, opsize=false;
    for(;;){                                     // legacy prefixes we accept: operand size only
        if(p[len]==0x66){ opsize=true; len++; continue; }
        break;
    }
    if((p[len]&0xF0)==0x40){ wide=(p[len]&8)!=0; len++; }   // REX
    uint8_t op=p[len++];
    int imm=opsize?2:4;
    if(op>=0x50&&op<=0x5F) return len;                         // push/pop reg
    if(op==0x90) return len;                                   // nop
    if(op>=0xB8&&op<=0xBF) return len+(wide?8:imm);            // mov reg, imm32/imm64
    if(op==0x6A) return len+1;                                 // push imm8
    if(op==0x68) return len+4;                                 // push imm32
    int m;
    switch(op){
        // op r/m, reg and op reg, r/m: add or adc sbb and sub xor cmp test mov lea movsxd xchg
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x84: case 0x85: case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8D: case 0x63:
            m=modrmLength(p+len); return m<0?-1:len+m;
        case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6:  // group with imm8
            m=modrmLength(p+len); return m<0?-1:len+m+1;
        case 0x81: case 0xC7:                                  // group with imm16/32
            m=modrmLength(p+len); return m<0?-1:len+m+imm;
        case 0x0F:
            if(p[len]==0x1F){ m=modrmLength(p+len+1); return m<0?-1:len+1+m; }  // multi-byte nop
            return -1;
        default:
            return -1;                                         // jumps, calls, ret, int3, anything else
    }
}

// Bytes of whole instructions at code that cover at least need bytes, or -1.
static int prologueLength(const uint8_t* code,int need){
    int total=0;
    while(total<need){
        int n=instructionLength(code+total);
        if(n<=0) return -1;
        total+=n;
    }
    return total;
}
