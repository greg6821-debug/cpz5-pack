// refdec.cpp — minimal CPZ5 decoder transcribed FAITHFULLY from arc_unpacker
//   src/dec/purple_software/cpz5/crypt.cc  +  cpz5_archive_decoder.cc  +  plugin.cc
//   +  src/algo/crypt/md5.cc (uses OpenSSL MD5 with custom IV, exactly like arc_unpacker).
// Purpose: independent validation that the TypeScript cpz5.ts encoder produces
//   output a faithful C++ decoder (matching arc_unpacker's crypto) can read.
//
// Build: g++ -O2 -o refdec refdec.cpp -lcrypto
// Usage: ./refdec <file.cpz5>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <openssl/md5.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

static inline u32 rotr32(u32 x, int b){ return (x>>b)|(x<<(32-b)); }
static inline u32 rotl32(u32 x, int b){ return (x<<b)|(x>>(32-b)); }
static inline u32 rdU32(const u8*p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((u32)p[3]<<24); }
static inline u64 rdU64(const u8*p){ u64 lo=rdU32(p); u64 hi=rdU32(p+4); return (hi<<32)|lo; }

struct Plugin {
    std::vector<u8> secret;
    std::array<size_t,4> hash_permutation;
    std::array<u32,4> hash_iv, hash_xor, hash_add;
    u32 crypt_23_mul;
    struct { u32 add1, add2; u8 tail_sub; } crypt_1a;
    struct { std::array<u32,4> addends; u32 init_key; } crypt_1c;
    struct { size_t start_pos; u8 tail_xor; } crypt_3;
};

static Plugin get_5v1(){
    Plugin p;
    p.secret = {
        0x89,0xF0,0x90,0xCD,0x82,0xB7,0x82,0xE9,0x88,0xAB,0x82,0xA2,0x8E,0x71,0x82,0xCD,
        0x83,0x8A,0x83,0x52,0x82,0xAA,0x82,0xA8,0x8E,0x64,0x92,0x75,0x82,0xAB,0x82,0xB5,
        0x82,0xBF,0x82,0xE1,0x82,0xA2,0x82,0xDC,0x82,0xB7,0x81,0x42,0x8E,0xF4,0x82,0xED,
        0x82,0xEA,0x82,0xBF,0x82,0xE1,0x82,0xA2,0x82,0xDC,0x82,0xB7,0x82,0xE6,0x81,0x60,
        0x81,0x41,0x82,0xC6,0x82,0xA2,0x82,0xA4,0x82,0xA9,0x82,0xE0,0x82,0xA4,0x8E,0xF4,
        0x82,0xC1,0x82,0xBF,0x82,0xE1,0x82,0xA2,0x82,0xDC,0x82,0xB5,0x82,0xBD,0x81,0xF4,
    };
    p.hash_permutation = {3,1,2,0};
    p.hash_iv = {0xC74A2B01,0xE7C8AB8F,0xD8BEDC4E,0x7302A4C5};
    p.hash_xor = {0,0,0,0};
    p.hash_add = {0,0,0,0};
    p.crypt_1a.add1=0x784C5962; p.crypt_1a.add2=0x01010101; p.crypt_1a.tail_sub=0x79;
    p.crypt_1c.addends={0,0x112233,0,0x34258765}; p.crypt_1c.init_key=0x2A65CB4E;
    p.crypt_3.start_pos=9; p.crypt_3.tail_xor=0xBC;
    p.crypt_23_mul=0x1A743125;
    return p;
}

// ---- plugin 5v2 (from plugin.cc) ----
static Plugin get_5v2(){
    Plugin p = get_5v1(); // base (crypt_1a/1c/3.start_pos inherited from base)
    p.secret = {
        0x89,0xF0,0x90,0xCD,0x82,0xB7,0x82,0xE9,0x88,0xAB,0x82,0xA2,0x8E,0x71,0x82,0xCD,
        0x83,0x8A,0x83,0x52,0x82,0xAA,0x82,0xA8,0x8E,0x64,0x92,0x75,0x82,0xAB,0x82,0xB5,
        0x82,0xBF,0x82,0xE1,0x82,0xA2,0x82,0xDC,0x82,0xB7,0x81,0x42,0x83,0x81,0x83,0x62,
        0x81,0x49,0x82,0xA9,0x82,0xED,0x82,0xA2,0x82,0xA2,0x82,0xC6,0x82,0xA9,0x8C,0xBE,
        0x82,0xC1,0x82,0xC4,0x82,0xE0,0x8B,0x96,0x82,0xB5,0x82,0xC4,0x82,0xA0,0x82,0xB0,
        0x82,0xC8,0x82,0xA2,0x82,0xF3,0x82,0xBE,0x82,0xA9,0x82,0xE7,0x82,0x9F,0x81,0x49,
    };
    p.hash_permutation = {1,2,3,0};
    p.hash_iv = {0x53FE9B2C,0xF2C93EA8,0xEE81BA59,0xA2C8973E};
    p.hash_xor = {0x49875325,0,0xAD7948B7,0};
    p.hash_add = {0,0x54F46D7D,0,0x1D0638AD};
    p.crypt_3.tail_xor=0xCB;
    p.crypt_23_mul=0x1A740235;
    return p;
}

static std::array<u8,16> md5_iv(const u8* in, size_t len, std::array<u32,4> iv){
    MD5_CTX ctx; MD5_Init(&ctx);
    ctx.A=iv[0]; ctx.B=iv[1]; ctx.C=iv[2]; ctx.D=iv[3];
    u8 out[16]; MD5_Update(&ctx,in,len); MD5_Final(out,&ctx);
    std::array<u8,16> r; memcpy(r.data(),out,16); return r;
}

static std::array<u32,4> get_hash(const Plugin&p, std::array<u32,4> in){
    u8 buf[16]; for(int i=0;i<4;i++){ u32 v=in[i]; buf[i*4]=v&0xff; buf[i*4+1]=(v>>8)&0xff; buf[i*4+2]=(v>>16)&0xff; buf[i*4+3]=(v>>24)&0xff; }
    auto hb = md5_iv(buf,16,p.hash_iv);
    std::array<u32,4> hd; for(int i=0;i<4;i++) hd[i]=rdU32(hb.data()+i*4);
    std::array<u32,4> r;
    for(int i=0;i<4;i++){ r[i]=hd[p.hash_permutation[i]]; r[i]^=p.hash_xor[i]; r[i]+=p.hash_add[i]; }
    return r;
}

static std::array<u8,256> get_table(const Plugin&p, u32 key, u32 seed){
    std::array<u8,256> t; for(int i=0;i<256;i++) t[i]=i;
    for(int i=0;i<256;i++){
        std::swap(t[(key>>16)&0xff], t[key&0xff]);
        std::swap(t[(key>>8)&0xff], t[(key>>24)&0xff]);
        key = seed + rotr32(key,2)*p.crypt_23_mul;
    }
    return t;
}

static void dec1a(u8* target, size_t size, const Plugin&p, u32 key){
    std::array<u32,24> table;
    size_t limit = std::min(table.size(), p.secret.size()/4);
    for(size_t i=0;i<limit;i++){ u32 s = rdU32(p.secret.data()+i*4); table[i] = s - key; }
    size_t shift = key;
    for(int i=0;i<3;i++) shift = (shift>>8)^key;
    shift = ((shift^0xFB)&0x0F)+7;
    size_t pos=5;
    u32* t32 = (u32*)target;
    for(size_t i=0;i<(size>>2);i++){
        u32 tmp1 = table[pos++] ^ t32[i];
        u32 tmp2 = tmp1 + p.crypt_1a.add1;
        t32[i] = rotr32(tmp2, shift) + p.crypt_1a.add2;
        pos %= 24;
    }
    u8* t8 = (u8*)(t32 + (size>>2));
    for(size_t i=0;i<(size&3);i++){
        u32 tmp1 = table[pos++] >> (4*(3-i));
        u32 tmp2 = tmp1 ^ t8[i];
        t8[i] = (u8)(tmp2 - p.crypt_1a.tail_sub);
        pos %= 24;
    }
}

static void dec1b(u8* target, size_t size, u32 key, std::array<u32,4> hash){
    static const std::array<u32,4> addends={0x76A3BF29,0,0x10000000,0};
    std::array<u32,4> table;
    for(int i=0;i<4;i++) table[i] = hash[i] ^ (key + addends[i]);
    size_t pos=0; u32 seed=0x76548AEF;
    u32* t32=(u32*)target;
    for(size_t i=0;i<(size>>2);i++){
        u32 tmp = (t32[i]^table[pos++]) - 0x4A91C262;
        t32[i] = rotl32(tmp,3) - seed;
        pos%=4; seed += 0x10FB562A;
    }
    u8* t8=(u8*)(t32+(size>>2));
    for(size_t i=0;i<(size&3);i++){ t8[i] = (u8)(((table[pos++]>>6) ^ t8[i]) + 0x37); pos%=4; }
}

static void dec1c(u8* target, size_t size, const Plugin&p, u32 key, std::array<u32,4> hash){
    std::array<u32,4> table;
    for(int i=0;i<4;i++) table[i] = hash[i] ^ (key + p.crypt_1c.addends[i]);
    size_t pos=0; u32 seed=p.crypt_1c.init_key;
    u32* t32=(u32*)target;
    for(size_t i=0;i<(size>>2);i++){
        u32 tmp = (t32[i]^table[pos++]) - seed;
        t32[i] = rotl32(tmp,2) + 0x37A19E8B;
        pos%=4; seed -= 0x139FA9B;
    }
    u8* t8=(u8*)(t32+(size>>2));
    for(size_t i=0;i<(size&3);i++){ t8[i] = (u8)(((table[pos++]>>4) ^ t8[i]) + 0x05); pos%=4; }
}

static void dec2(u8* target, size_t size, const Plugin&p, u32 key, u32 seed, u8 px){
    auto table = get_table(p,key,seed);
    for(size_t i=0;i<size;i++) target[i] = table[target[i]^px];
}

static void dec3(u8* target, size_t size, const Plugin&p, u32 key, u32 seed, std::array<u32,4> hash, u32 entry_key){
    auto table = get_table(p,key,seed);
    u32 yat[24];
    u8* yb=(u8*)yat;
    u32 hk = hash[1]>>2;
    for(int i=0;i<96;i++) yb[i] = (u8)(table[p.secret[i]] ^ hk);
    for(int i=0;i<24;i++) yat[i] ^= entry_key;
    size_t pos = p.crypt_3.start_pos;
    u32 yak = 0x2547A39E;
    u32* t32=(u32*)target;
    for(size_t i=0;i<(size>>2);i++){
        u32 tmp1 = t32[i];
        u32 tmp2 = yat[pos&0x0F] >> 1;
        u32 tmp3 = yat[(yak>>6)&0x0F];
        u32 ft = tmp1 ^ tmp2 ^ tmp3;
        t32[i] = hash[yak&3] ^ (ft - entry_key);
        pos++;
        yak += t32[i] + entry_key;
    }
    u8* t8=(u8*)(t32+(size>>2));
    for(size_t i=0;i<(size&3);i++) t8[i] = table[t8[i]^p.crypt_3.tail_xor];
}

int main(int argc, char** argv){ setvbuf(stdout,NULL,_IONBF,0);
    if(argc<2){ fprintf(stderr,"usage: %s file.cpz5 [plugin:5v1|5v2|both]\n",argv[0]); return 1; }
    std::string which = argc>=3 ? argv[2] : "both";
    FILE*f=fopen(argv[1],"rb"); if(!f){ perror("open"); return 1; }
    fseek(f,0,SEEK_END); long fsz=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<u8> buf(fsz); fread(buf.data(),1,fsz,f); fclose(f);
    u32 dirCount = rdU32(buf.data()+4) ^ 0xFE3A53D9;
    u32 dirTableSize = rdU32(buf.data()+8) ^ 0x37F298E7;
    u32 fileTableSize = rdU32(buf.data()+12) ^ 0x7A6F3A2C;
    std::array<u32,4> md5 = { rdU32(buf.data()+32)^0x43DE7C19, rdU32(buf.data()+36)^0xCC65F415, rdU32(buf.data()+40)^0xD016A93C, rdU32(buf.data()+44)^0x97A3BA9A };
    u32 mainKey = rdU32(buf.data()+48) ^ 0xAE7D39BF;
    u32 tableSize = dirTableSize + fileTableSize;
    u32 dataStart = 64 + tableSize;
    printf("dirCount=%u dirTableSize=%u fileTableSize=%u mainKey=%08x dataStart=%u bufLen=%ld\n", dirCount, dirTableSize, fileTableSize, mainKey, dataStart, fsz);

    std::vector<Plugin> plugins;
    if(which=="5v1"||which=="both") plugins.push_back(get_5v1());
    if(which=="5v2"||which=="both") plugins.push_back(get_5v2());

    for(auto& p : plugins){
        printf("\n========== PLUGIN %s (mul=%08x tail3=%02x) ==========\n",
            &p == plugins.data() ? (plugins.size()>1?"5v1":"sel") : "5v2",
            p.crypt_23_mul, p.crypt_3.tail_xor);
        auto hash = get_hash(p, md5);
        printf("hash: %08x %08x %08x %08x\n", hash[0],hash[1],hash[2],hash[3]);
        std::vector<u8> idx(buf.begin()+64, buf.begin()+64+tableSize);
        dec1a(idx.data(), tableSize, p, mainKey ^ 0x3795B39A);
        dec2(idx.data(), dirTableSize, p, mainKey, hash[1], 0x3A);
        dec1b(idx.data(), dirTableSize, mainKey, hash);
        printf("--- dir table (first %u bytes) ---\n", dirTableSize);
        for(size_t i=0;i<dirTableSize && i<64;i++) printf("%02x", idx[i]); printf("\n");

        size_t cur=0;
        struct Dir { u32 fileCount, fto, ftk; std::string name; size_t fsize; };
        std::vector<Dir> dirs;
        bool ok=true;
        for(u32 d=0; d<dirCount && ok; d++){
            size_t eo=cur;
            if(cur+16>dirTableSize){ printf("  dir[%u] OOB\n",d); ok=false; break; }
            u32 il=rdU32(idx.data()+cur); cur+=4;
            u32 fc=rdU32(idx.data()+cur); cur+=4;
            u32 fto=rdU32(idx.data()+cur); cur+=4;
            u32 ftk=rdU32(idx.data()+cur); cur+=4;
            std::string nm; while(cur<dirTableSize && idx[cur]) nm+=(char)idx[cur++];
            cur++;
            dirs.push_back({fc,fto,ftk,nm,0});
            cur = eo+il;
            printf("  dir[%u] il=%u fc=%u fto=%u ftk=%08x name=\"%s\"\n", d, il, fc, fto, ftk, nm.c_str());
        }
        if(!ok){ printf("  (dir parse failed)\n"); continue; }
        for(size_t d=0; d<dirs.size(); d++){
            if(d+1<dirs.size()) dirs[d].fsize = dirs[d+1].fto - dirs[d].fto;
            else dirs[d].fsize = tableSize - dirTableSize - dirs[d].fto;
            printf("  dir[%zu] fsize=%u\n", d, (u32)dirs[d].fsize);
        }

        int entryIdx=0;
        for(auto&d:dirs){
            if(d.fto + d.fsize > fileTableSize){ printf("  dir file region OOB\n"); ok=false; break; }
            u8* region = idx.data() + dirTableSize + d.fto;
            dec2(region, d.fsize, p, mainKey, hash[2], 0x7E);
            dec1c(region, d.fsize, p, d.ftk, hash);
            printf("  --- file table for dir \"%s\" (first 64 bytes) ---\n    ", d.name.c_str());
            for(size_t i=0;i<d.fsize && i<64;i++) printf("%02x", region[i]); printf("\n");
            size_t c=0;
            for(u32 fi=0; fi<d.fileCount && ok; fi++){
                if(c+24>d.fsize){ printf("  entry[%u] OOB c=%zu fsize=%u\n",fi,c,(u32)d.fsize); ok=false; break; }
                size_t eo=c;
                u32 il=rdU32(region+c); c+=4;
                u64 rel=rdU64(region+c); c+=8;
                u32 sz=rdU32(region+c); c+=4;
                u32 skip4=rdU32(region+c); c+=4;
                u32 tmp=rdU32(region+c); c+=4;
                std::string nm; while(c<d.fsize && region[c]) nm+=(char)region[c++]; c++;
                if(il<24 || eo+il>d.fsize){ printf("  entry[%u] bad il=%u at=%zu\n",fi,il,eo); ok=false; break; }
                u32 ekey = ((mainKey ^ (d.ftk + tmp)) + dirCount - 0x5C29E87B);
                printf("  entry[%d] il=%u rel=%llu sz=%u tmp=%08x ekey=%08x name=\"%s\"",
                    entryIdx, il, (unsigned long long)rel, sz, tmp, ekey, nm.c_str());
                if(dataStart+rel+sz > (u32)fsz){ printf(" [DATA OOB!]"); ok=false; }
                printf("\n");
                c = eo+il; entryIdx++;
                if(entryIdx>=8){ printf("  (stopping after 8 entries)\n"); goto next_plugin; }
            }
        }
        next_plugin:;
        if(ok) printf("  >> PLUGIN %s PARSE OK\n", &p==plugins.data()?(plugins.size()>1?"5v1":"sel"):"5v2");
        else printf("  >> PLUGIN %s FAILED\n", &p==plugins.data()?(plugins.size()>1?"5v1":"sel"):"5v2");
    }
    return 0;
}

// standalone table dump
