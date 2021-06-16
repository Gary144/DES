/***********************************************************************************************
* 作    者：曾光辉
* 说    明：此处实现的SHA1算法中字符串的位长度不得大于2^16 bit
***********************************************************************************************/
#include<stddef.h>
#include<stdio.h>
#include<math.h>

// Define consts.
#define S_LEFT(x, n)    (((x) << (n)) | ((x) >> (32-(n))))//rotate left.

#define KT1        0x5a827999
#define KT2        0x6ed9eba1
#define KT3        0x8f1bbcdc
#define KT4        0xca62c1d6

// Grobals.
static unsigned long sha1_A,sha1_B,sha1_C,sha1_D,sha1_E;
static unsigned long sha1_w[80];
static unsigned long sha1_temp;
static unsigned long sha1_m[16];
static unsigned long sha1_h[5];

///////////////////////////////////////////////////////////////////////////////
// Function Names: unsigned long ch();unsigned long() parity();unsigned long maj()
// Feature: This functions was declared by the sha1 algrithm descripted in SECURE HASH STANDARD.
///////////////////////////////////////////////////////////////////////////////
static unsigned long ch(unsigned long x,unsigned long y,unsigned long z)
{
	return (x&y)|((~x)&z);
}

static unsigned long parity(unsigned long x,unsigned long y,unsigned long z)
{
	return x^y^z;
}

static unsigned long maj(unsigned long x,unsigned long y,unsigned long z)
{
	return (x&y)|(x&z)|(y&z);
}

///////////////////////////////////////////////////////////////////////////////
// Function Name: void sha_hInit()
// Feature: Put the values defined by the sha1 algrithm to sha1_h[] buffer.
///////////////////////////////////////////////////////////////////////////////
static void sha_hInit()
{
	sha1_h[0]=0x67452301;
	sha1_h[1]=0xefcdab89;
	sha1_h[2]=0x98badcfe;
	sha1_h[3]=0x10325476;
	sha1_h[4]=0xc3d2e1f0;
}

///////////////////////////////////////////////////////////////////////////////
// Function Name: void sha_ByteToWord()
// Feature: To transform the 'unsigned char' data to the 'unsigned long' data.
///////////////////////////////////////////////////////////////////////////////
static void sha_ByteToWord(unsigned char* ptr,unsigned char n)
{
	unsigned char i,j;
	unsigned char* pTmp;
	
	pTmp=ptr;
	for(i=0;i<n;i++)
	{
		sha1_m[i]=0x00000000;
		for(j=0;j<4;j++)
		{
			sha1_m[i]=sha1_m[i]<<8;
			sha1_m[i]+=*pTmp;
			pTmp++;
		}
	}
}
///////////////////////////////////////////////////////////////////////////////
// Function Name: unsigned long sha_GetStrLen(unsigned char* ptr)
// Feature: Get the length of sha1_A string pointed by the pointer ptr;
///////////////////////////////////////////////////////////////////////////////
static unsigned long sha_GetStrLen(unsigned char* ptr)
{
	unsigned long len=0;
	unsigned char* pTmp;
	
	pTmp=ptr;
	while(pTmp!=NULL&&(*pTmp)!='\0')
	{
		len++;
		pTmp++;
	}//获取字符串的长度
	return len;
}

///////////////////////////////////////////////////////////////////////////////
// Function Names: void sha_ClearM();void sha_ClearW();
// Feature: Filled the array sha1_m[] or array sha1_w[] with 0.
///////////////////////////////////////////////////////////////////////////////
static void sha_ClearM()
{
	unsigned char i;
	
	for(i=0;i<16;i++)
	{
		sha1_m[i]=0x00000000;
	}
}

static void sha_ClearW()
{
	unsigned char i;
	for(i=0;i<80;i++)
	{
		sha1_w[i]=0x00000000;
	}
}

///////////////////////////////////////////////////////////////////////////////
// Function Name: void CopyM2W()
// Feature: Copy the value of sha1_m[16] to sha1_w[0]..sha1_w[15]
///////////////////////////////////////////////////////////////////////////////
static void CopyM2W()
{
	unsigned char i;
	
	for(i=0;i<16;i++)
	{
		sha1_w[i]=sha1_m[i];
	}
}
///////////////////////////////////////////////////////////////////////////////
// Function Name: void AddLenWord()
// Feature: Add the 64-bit string bit length to sha1_m[14]..sha1_m[15]. The low part is
//          to sha1_m[15] and the high part to sha1_m[14].
///////////////////////////////////////////////////////////////////////////////

static void AddLenWord(unsigned long len)
{
	sha1_m[14]=0x00000000;
	sha1_m[15]=len*8;
}

///////////////////////////////////////////////////////////////////////////////
// Function Name: void sha_Print()
// Feature: Output the sha1 code sha1_h[0..5] via the UART of 51 MCU.
///////////////////////////////////////////////////////////////////////////////
static void sha_Print()
{
	unsigned char i;
	
	for(i=0;i<5;i++)
	{
//		printf("%04lx ",sha1_h[i]);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Function Name：void ProChunk()
// Feature：To compute sha1_A sha1 value of datas in blocks of fixed size(512 bit)
///////////////////////////////////////////////////////////////////////////////
static void ProChunk()
{
	short t;
	unsigned long wTmp;
	
	sha_ClearW();
	CopyM2W();
	
	for(t=16;t<80;t++)
	{
		wTmp=sha1_w[t-3]^sha1_w[t-8]^sha1_w[t-14]^sha1_w[t-16];
		sha1_w[t]=S_LEFT(wTmp,1);
	}
	
	sha1_A=sha1_h[0];
	sha1_B=sha1_h[1];
	sha1_C=sha1_h[2];
	sha1_D=sha1_h[3];
	sha1_E=sha1_h[4];
	
	for(t=0;t<80;t++)
	{
		sha1_temp=S_LEFT(sha1_A,5);
		sha1_temp=sha1_temp+sha1_E;
		sha1_temp=sha1_temp+sha1_w[t];
		if(0<=t&&t<=19)
		{
			sha1_temp+=ch(sha1_B,sha1_C,sha1_D)+KT1;        
		}
		if(20<=t&&t<=39)
		{
			sha1_temp+=parity(sha1_B,sha1_C,sha1_D)+KT2;
		}
		if(40<=t&&t<=59)
		{
			sha1_temp+=maj(sha1_B,sha1_C,sha1_D)+KT3;
		}
		if(60<=t&&t<=79)
		{
			sha1_temp+=parity(sha1_B,sha1_C,sha1_D)+KT4;
		}
		sha1_E=sha1_D;
		sha1_D=sha1_C;
		sha1_C=S_LEFT(sha1_B,30);
		sha1_B=sha1_A;
		sha1_A=sha1_temp;
	}
	sha1_h[0]+=sha1_A;
	sha1_h[1]+=sha1_B;
	sha1_h[2]+=sha1_C;
	sha1_h[3]+=sha1_D;
	sha1_h[4]+=sha1_E;
}

///////////////////////////////////////////////////////////////////////////////
// Function Name：void Sha1()
// Feature：To calculate the SHA1 value of sha1_A given string whos bit-length is random.
// Note: 本程序中待处理的字符串长度不得大于2^16 bit
///////////////////////////////////////////////////////////////////////////////
void SHA1_Test(unsigned char* ptr)//因为是非标版，所以输入必须为8字节的倍数
{
	unsigned short len,len1;//字符串长度暂存器
	unsigned char* pTmp;//待处理字符串指针复本
	unsigned char n,mm;
	
	len=sha_GetStrLen(ptr);//获取字符串的长度
	len1=len;
	pTmp=ptr;
	
	sha_hInit();
	//处理完整的（足够512位）的数据块
	while((len/64)>0)
	{        
		//写入w的前16个字
		sha_ByteToWord(pTmp,16);
		ProChunk();//数据块处理
		sha_ClearM();
		len-=64;//处理完一块后，总数据长度减512 bit
		pTmp+=64;
	}//先处理完整的块
	
	//把剩下的数据先送到M缓冲区
	sha_ByteToWord(pTmp,len/4);
	
	n=len%4;
	mm=len/4;
	//数据块填充
	sha1_m[mm]=0x00000000;
	switch(n)
	{
		case 0:
			sha1_m[mm] |= 0x80000000;
		break;
		case 1:
			sha1_m[mm]  = *pTmp;
			sha1_m[mm]  = sha1_m[mm]<<24;
			sha1_m[mm] |= 0x00800000;
		break;
		case 2:
			sha1_m[mm]  = *pTmp;
			sha1_m[mm]  = sha1_m[mm]<<8;
			sha1_m[mm] += *(pTmp+1);
			sha1_m[mm]  = sha1_m[mm]<<16;
			sha1_m[mm] |= 0x00008000;
		break;
		case 3:
			sha1_m[mm]  = *pTmp;
			sha1_m[mm]  = sha1_m[mm]<<8;
			sha1_m[mm] += *(pTmp+1);
			sha1_m[mm]  = sha1_m[mm]<<8;
			sha1_m[mm] += *(pTmp+2);
			sha1_m[mm]  = sha1_m[mm]<<8;
			sha1_m[mm] |= 0x00000080;
		break;
		default:;
	}
	
	// 当大于等于448位时，需添加额外的数据块，即最后剩下数据需要两次才能处理完
	if(len>=56&&len<64)
	{            
		ProChunk();
		//clear sha1_m
		sha_ClearM();
	}
	AddLenWord(len1);
	ProChunk();    
	
	//输出结果
	sha_Print();
} 

