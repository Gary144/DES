/******************************************************************************************************************
  TEA加密解密算法
  TEA(Tiny Encryption Algorithm)是一种简单高效的加密算法，以加密解密速度快，实现简单著称。
  算法很简单，TEA算法每一次可以操作64-bit(8-byte)，采用128-bit(16-byte)作为key，算法采用迭代的形式，
  推荐的迭代轮数是64轮，最少32轮。
******************************************************************************************************************/
#define MX 			(z>>5^y<<2)+(y>>3^z<<4)^(sum^y)+(k[p&3^e]^z)
#define DELTA 		0x9e3779b9
#define S_LOOPTIME  5
#define BLOCK_SIZE  32   //PAGE_SIZE,根据你所要加密的数据包长度修改此参数(单位:字节)

void TEA_Encrypt( unsigned char* buf, unsigned char* key )
{
	unsigned char  n=BLOCK_SIZE/4;
	unsigned long *v=(unsigned long *)buf;
	unsigned long *k=(unsigned long *)key;
	unsigned long z = v[n - 1],y = v[0],sum = 0,e ;
	unsigned char p,q ;
	// Coding Part 
	
	q = S_LOOPTIME + 52 / n ;
	while ( q-- > 0 )
	{
		sum += DELTA ;
		e = sum >> 2 & 3 ;
		for ( p = 0 ; p < n - 1 ; p++ )
			y = v[p + 1],
			z = v[p] += MX;
		y = v[0] ;
		z = v[n - 1] += MX;
	}
}

void TEA_Decrpyt( unsigned char* buf, unsigned char* key )
{
	unsigned char n=BLOCK_SIZE/4;
	unsigned long *v=(unsigned long *)buf;
	unsigned long *k=(unsigned long *)key;
	unsigned long z = v[n - 1],y = v[0],sum = 0,e ;
	unsigned char p,q ;
	
	//Decoding Part...
	q = S_LOOPTIME + 52 / n ;
	sum = q * DELTA ;
	while ( sum != 0 )
	{
		e = sum >> 2 & 3 ;
		for ( p = n - 1 ; p > 0 ; p-- )
			z = v[p - 1],
			y = v[p] -= MX;
		z = v[n - 1] ;
		y = v[0] -= MX;
		sum -= DELTA ;
	}
}

#include "string.h"
void TEA_Test(void)
{
	unsigned char dat[16]="0123456789ABCDEF";
	unsigned char TEA_key[16];
	memcpy(TEA_key,"0123456789abcdef",16);//做运算之前先要设置好密钥，这里只是设置密钥的DEMO。

	TEA_Encrypt(dat,TEA_key);      //TEA加密，数组dat里面的新内容就是加密后的数据。
	TEA_Decrpyt(dat,TEA_key);      //密文数据存放在dat里面，经TEA解密就能得到之前的明文。
}
