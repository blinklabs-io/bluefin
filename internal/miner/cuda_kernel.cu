// Copyright 2026 Blink Labs Software
// SPDX-License-Identifier: Apache-2.0

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NONCE_OFFSET 4
#define NONCE_LEN 16
#define MAX_STATE_LEN 192
#define THREADS_PER_BLOCK 256

static char last_error[256];
static void set_error(cudaError_t error, const char *operation) {
    snprintf(last_error, sizeof(last_error), "%s: %s", operation,
             cudaGetErrorString(error));
}
extern "C" const char *bluefin_cuda_last_error(void) { return last_error; }

struct bluefin_cuda_backend {
    int device;
    int batch_size;
    uint8_t *state;
    uint8_t *base_nonce;
    uint32_t *result;
};

extern "C" void bluefin_cuda_destroy(bluefin_cuda_backend *backend);

__constant__ uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0b5e9,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

__device__ __forceinline__ uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
__device__ void compress(uint32_t *d, const uint32_t *in) {
    uint32_t w[64];
    #pragma unroll
    for (int i=0;i<16;i++) w[i]=in[i];
    #pragma unroll
    for (int i=16;i<64;i++) w[i]=(rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10))+w[i-7]+(rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3))+w[i-16];
    uint32_t a=d[0],b=d[1],c=d[2],e=d[4],f=d[5],g=d[6],h=d[7],x=d[3];
    #pragma unroll
    for (int i=0;i<64;i++) { uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25); uint32_t ch=(e&f)^(~e&g); uint32_t t1=h+s1+ch+K[i]+w[i]; uint32_t s0=rotr(a,2)^rotr(a,13)^rotr(a,22); uint32_t maj=(a&b)^(a&c)^(b&c); uint32_t t2=s0+maj; h=g;g=f;f=e;e=x+t1;x=c;c=b;b=a;a=t1+t2; }
    d[0]+=a;d[1]+=b;d[2]+=c;d[3]+=x;d[4]+=e;d[5]+=f;d[6]+=g;d[7]+=h;
}
__device__ void sha256(const uint8_t *data, int len, uint32_t *d) {
    uint8_t buf[256]; memset(buf,0,sizeof(buf)); for(int i=0;i<len;i++) buf[i]=data[i]; buf[len]=0x80; uint64_t bits=(uint64_t)len*8; for(int i=0;i<8;i++) buf[((len+9+63)/64)*64-1-i]=(uint8_t)(bits>>(8*i));
    d[0]=0x6a09e667;d[1]=0xbb67ae85;d[2]=0x3c6ef372;d[3]=0xa54ff53a;d[4]=0x510e527f;d[5]=0x9b05688c;d[6]=0x1f83d9ab;d[7]=0x5be0cd19;
    int n=((len+9+63)/64); for(int b=0;b<n;b++){uint32_t w[16];for(int i=0;i<16;i++){int p=b*64+i*4;w[i]=((uint32_t)buf[p]<<24)|((uint32_t)buf[p+1]<<16)|((uint32_t)buf[p+2]<<8)|buf[p+3];}compress(d,w);}
}
__device__ void sha256_32(const uint32_t *in, uint32_t *d) { uint32_t w[16]={}; for(int i=0;i<8;i++)w[i]=in[i];w[8]=0x80000000;w[15]=256;d[0]=0x6a09e667;d[1]=0xbb67ae85;d[2]=0x3c6ef372;d[3]=0xa54ff53a;d[4]=0x510e527f;d[5]=0x9b05688c;d[6]=0x1f83d9ab;d[7]=0x5be0cd19;compress(d,w); }
__device__ uint8_t hash_byte(const uint32_t *h,int i){return i<32?(uint8_t)(h[i/4]>>(24-8*(i%4))):0;}
__device__ void difficulty(const uint32_t *h,uint32_t *lz,uint32_t *diff){*lz=0;*diff=0;for(int i=0;i<32;i++){uint8_t c=hash_byte(h,i);if(c==0){*lz+=2;continue;}if((c&0xf0)==0){*lz+=1;*diff=c*4096+hash_byte(h,i+1)*16+hash_byte(h,i+2)/16;}else *diff=c*256+hash_byte(h,i+1);return;}}

__global__ void tuna_search(const uint8_t *state,int state_len,const uint8_t *base_nonce,uint32_t batch_size,uint32_t round,uint32_t target_lz,uint32_t target_diff,uint32_t *result) {
    uint32_t gid=blockIdx.x*blockDim.x+threadIdx.x; if(gid>=batch_size)return; uint8_t local[MAX_STATE_LEN],nonce[NONCE_LEN]; for(int i=0;i<state_len;i++)local[i]=state[i];for(int i=0;i<16;i++)nonce[i]=base_nonce[i];uint32_t v=gid;nonce[0]^=v>>24;nonce[1]^=v>>16;nonce[2]^=v>>8;nonce[3]^=v;nonce[4]^=round>>24;nonce[5]^=round>>16;nonce[6]^=round>>8;nonce[7]^=round;for(int i=0;i<16;i++)local[NONCE_OFFSET+i]=nonce[i];uint32_t h1[8],h2[8],lz,diff;sha256(local,state_len,h1);sha256_32(h1,h2);difficulty(h2,&lz,&diff);if(!(lz>target_lz||(lz==target_lz&&diff<target_diff)))return;if(atomicCAS(result,0,1)!=0)return;for(int i=0;i<16;i++)result[1+i/4]|=(uint32_t)nonce[i]<<(24-8*(i%4));for(int i=0;i<32;i++)result[5+i/4]|=(uint32_t)hash_byte(h2,i)<<(24-8*(i%4));
}

extern "C" int bluefin_cuda_create(int device,int batch_size,bluefin_cuda_backend **out){
    cudaError_t e=cudaSetDevice(device);if(e!=cudaSuccess){set_error(e,"cudaSetDevice");return -1;}bluefin_cuda_backend*b=new bluefin_cuda_backend{device,batch_size,nullptr,nullptr,nullptr};e=cudaMalloc(&b->state,MAX_STATE_LEN);if(e==cudaSuccess)e=cudaMalloc(&b->base_nonce,NONCE_LEN);if(e==cudaSuccess)e=cudaMalloc(&b->result,13*sizeof(uint32_t));if(e!=cudaSuccess){set_error(e,"cudaMalloc");bluefin_cuda_destroy(b);return -1;}*out=b;return 0;
}
extern "C" int bluefin_cuda_search(bluefin_cuda_backend*b,const uint8_t*state,int len,uint32_t lz,uint32_t diff,uint32_t round,const uint8_t*base,uint8_t*nonce,uint8_t*hash){
    if(!b||len<=0||len>MAX_STATE_LEN){snprintf(last_error,sizeof(last_error),"invalid CUDA search arguments");return -1;}cudaError_t e=cudaSetDevice(b->device);if(e==cudaSuccess)e=cudaMemcpy(b->state,state,len,cudaMemcpyHostToDevice);if(e==cudaSuccess)e=cudaMemcpy(b->base_nonce,base,16,cudaMemcpyHostToDevice);if(e==cudaSuccess)e=cudaMemset(b->result,0,13*sizeof(uint32_t));if(e!=cudaSuccess){set_error(e,"CUDA upload");return -1;}int blocks=(b->batch_size+THREADS_PER_BLOCK-1)/THREADS_PER_BLOCK;tuna_search<<<blocks,THREADS_PER_BLOCK>>>(b->state,len,b->base_nonce,(uint32_t)b->batch_size,round,lz,diff,b->result);e=cudaGetLastError();if(e==cudaSuccess)e=cudaDeviceSynchronize();if(e!=cudaSuccess){set_error(e,"CUDA kernel");return -1;}uint32_t r[13];e=cudaMemcpy(r,b->result,sizeof(r),cudaMemcpyDeviceToHost);if(e!=cudaSuccess){set_error(e,"CUDA download");return -1;}if(!r[0])return 0;for(int i=0;i<4;i++)for(int j=0;j<4;j++)nonce[i*4+j]=(uint8_t)(r[1+i]>>(24-8*j));for(int i=0;i<8;i++)for(int j=0;j<4;j++)hash[i*4+j]=(uint8_t)(r[5+i]>>(24-8*j));return 1;
}
extern "C" void bluefin_cuda_destroy(bluefin_cuda_backend*b){if(!b)return;cudaSetDevice(b->device);cudaFree(b->state);cudaFree(b->base_nonce);cudaFree(b->result);delete b;}
