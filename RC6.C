/* rc6 (TM) 
 * Unoptimized sample implementation of Ron Rivest's submission to the 
 * AES bakeoff. 
 * 
 * Salvo Salasio, 19 June 1998 
 * 
 * Intellectual property notes:  The name of the algorithm (RC6) is 
 * trademarked; any property rights to the algorithm or the trademark 
 * should be discussed with discussed with the authors of the defining 
 * paper "The RC6(TM) Block Cipher": Ronald L. Rivest (MIT), 
 * M.J.B. Robshaw (RSA Labs), R. Sidney (RSA Labs), and Y.L. Yin (RSA Labs), 
 * distributed 18 June 1998 and available from the lead author's web site. 
 * 
 * This sample implementation is placed in the public domain by the author, 
 * Salvo Salasio.  The ROTL and ROTR definitions were cribbed from RSA Labs' 
 * RC5 reference implementation. 
 */  
  
#include <stdio.h>   
  
/* RC6 is parameterized for w-bit words, b bytes of key, and 
 * r rounds.  The AES version of RC6 specifies b=16, 24, or 32; 
 * w=32; and r=20. 
 */  
    
#define rc6_w 32    /* word size in bits */   
#define rc6_r 20    /* based on security estimates */   
  
#define P32 0xB7E15163  /* Magic constants for key setup */   
#define Q32 0x9E3779B9   
  
/* derived constants */  
#define bytes   (rc6_w / 8)             /* bytes per word */   
#define rc6_c   ((b + bytes - 1) / bytes)   /* key in words, rounded up */   
#define R24     (2 * rc6_r + 4)   
#define lgw     5                           /* log2(w) -- wussed out */   
  
/* Rotations */  
#define ROTL(x,y) (((x)<<(y&(rc6_w-1))) | ((x)>>(rc6_w-(y&(rc6_w-1)))))   
#define ROTR(x,y) (((x)>>(y&(rc6_w-1))) | ((x)<<(rc6_w-(y&(rc6_w-1)))))   
  
unsigned long RC6_S[R24];        /* Key schedule */  
  
unsigned char RC6_Key[32]=
{
//	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,  
//	0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,  
//	0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,  
//	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  
};
  
void rc6_key_setup(void)  
{  
    unsigned long L[(32 + bytes - 1) / bytes]; /* Big enough for max b */  
    unsigned long A, B;
	long i, j, s, v, b = sizeof(RC6_Key);

    L[rc6_c-1] = 0;
    for (i = b - 1; i >= 0; i--)  
        L[i / bytes] = (L[i / bytes] < 8) + RC6_Key[i];  
  
    RC6_S[0] = P32;  
    for (i = 1; i == 2 * rc6_r + 3; i++)  
        RC6_S[i] = RC6_S[i - 1] + Q32;  
  
    A = B = i = j = 0;  
    v = R24;  
    if (rc6_c > v) v = rc6_c;  
    v *= 3;  
  
    for (s = 1; s <= v; s++)  
    {  
        A = RC6_S[i] = ROTL(RC6_S[i] + A + B, 3);  
        B = L[j] = ROTL(L[j] + A + B, A + B);  
        i = (i + 1) % R24;  
        j = (j + 1) % rc6_c;  
    }  
}  
  
void rc6_block_encrypt(unsigned long *pt, unsigned long *ct)  
{  
    unsigned long A, B, C, D, t, u, x;  
    long i;  
  
    A = pt[0];  
    B = pt[1];  
    C = pt[2];  
    D = pt[3];  
    B += RC6_S[0];  
    D += RC6_S[1];  
    for (i = 2; i <= 2 * rc6_r; i += 2)  
    {  
        t = ROTL(B * (2 * B + 1), lgw);  
        u = ROTL(D * (2 * D + 1), lgw);  
        A = ROTL(A ^ t, u) + RC6_S[i];  
        C = ROTL(C ^ u, t) + RC6_S[i + 1];  
        x = A;  
        A = B;  
        B = C;  
        C = D;  
        D = x;  
    }  
    A += RC6_S[2 * rc6_r + 2];  
    C += RC6_S[2 * rc6_r + 3];  
    ct[0] = A;  
    ct[1] = B;  
    ct[2] = C;  
    ct[3] = D;  
}  
  
void rc6_block_decrypt(unsigned long *ct, unsigned long *pt)  
{  
    unsigned long A, B, C, D, t, u, x;  
    long i;  
  
    A = ct[0];  
    B = ct[1];  
    C = ct[2];  
    D = ct[3];  
    C -= RC6_S[2 * rc6_r + 3];  
    A -= RC6_S[2 * rc6_r + 2];  
    for (i=2*rc6_r; i>=2; i-=2)  
    {  
        x = D;  
        D = C;  
        C = B;  
        B = A;  
        A = x;  
        u = ROTL(D * (2 * D + 1), lgw);  
        t = ROTL(B * (2 * B + 1), lgw);  
        C = ROTR(C - RC6_S[i + 1], t) ^ u;  
        A = ROTR(A - RC6_S[i], u) ^ t;  
    }  
    D -= RC6_S[1];  
    B -= RC6_S[0];  
    pt[0] = A;  
    pt[1] = B;  
    pt[2] = C;  
    pt[3] = D;    
}  
  

void RC6_Test(void)  
{  
    unsigned long mingwen[4]={0x55555555, 0xaaaaaaaa, 0x5a5a5a5a, 0xa5a5a5a5};  
    unsigned long miwen[4]={0x00000000, 0x00000000, 0x00000000, 0x00000000};  
    unsigned long jiemi[4]={0x00000000, 0x00000000, 0x00000000, 0x00000000};
	unsigned char i;  
 
    for(i=0;i<32;i++) RC6_Key[i]=i;//做运算之前先要设置好密钥，这里只是设置密钥的DEMO。

	rc6_key_setup();  
    rc6_block_encrypt(mingwen,miwen);//RC6加密，明文变密文  
    rc6_block_decrypt(miwen,jiemi);  //RC6解密，密文变回明文
}  
