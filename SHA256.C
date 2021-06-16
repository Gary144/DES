/***********************************************************************************************
* 作    者：曾光辉
* 说    明：此处实现的SHA256算法中字符串的位长度并不是任意长度（0~2^64）的，而是在0~2^32.
***********************************************************************************************/
#include<stddef.h>
#include<stdio.h>

/*算法规定的函数或宏*/
#define SHR(x,n)     ((x)>>(n))
#define ROTR(x,n)    (((x)>>(n)) | ((x)<<(32-(n))))
#define CH(sha256_a,sha256_b,sha256_c)    	(((sha256_a)&(sha256_b)) ^ ((~sha256_a)&(sha256_c)))
#define MAJ(sha256_a,sha256_b,sha256_c) 	(((sha256_a)&(sha256_b)) ^ ((sha256_a)&(sha256_c)) ^ ((sha256_b)&(sha256_c)))
#define E0(x)        (ROTR((x),2) ^ ROTR((x),13) ^ ROTR((x),22))
#define E1(x)        (ROTR((x),6) ^ ROTR((x),11) ^ ROTR((x),25))
#define Q0(x)        (ROTR((x),7) ^ ROTR((x),18) ^ SHR((x),3))
#define Q1(x)        (ROTR((x),17) ^ ROTR((x),19) ^ SHR((x),10))

unsigned long sha256_hh[8];//sha256码暂存器
unsigned long sha256_a,sha256_b,sha256_c,sha256_d,sha256_e,sha256_f,sha256_g,sha256_h;//中间变量
unsigned long sha256_w[64];//工作暂存器
unsigned long sha256_K[64]=
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};//原算法规定的常量

/***********************************************************************************************
* 函数名称：unsigned long sha256_GetStrLen(unsigned char* ptr)
* 功    能：获取字符串的字节长度
* 参    数：字符串指针--ptr
* 返 回 值：字符串长度
***********************************************************************************************/
unsigned long sha256_GetStrLen(unsigned char* ptr)
{
	unsigned char* pTmp;
	unsigned long len=0;
	
	pTmp=ptr;
	
	while(pTmp!=NULL&&(*pTmp!='\0'))
	{
		len++;
		pTmp++;
	}
	return len;
}

/***********************************************************************************************
* 函数名称：void sha256_AddBitLen(unsigned long blen)
* 功    能：在工作暂存区末尾添加字符串位长度信息
***********************************************************************************************/
void sha256_AddBitLen(unsigned long blen)
{
	sha256_w[14]=0x00000000;
	sha256_w[15]=blen;
}

/***********************************************************************************************
* 函数名称：void sha256_ByteToWord(unsigned char* ptr,unsigned char n)
* 功    能：将以字节（8位）为单位存储的字符串转换成以字（32位）为单位存储。
* 参    数：转换的字的个数--n      字符串指针--*ptr
***********************************************************************************************/
void sha256_ByteToWord(unsigned char* ptr,unsigned char n)
{
	unsigned char* pTmp;
	unsigned char i,j;
	
	pTmp=ptr;
	
	for(i=0;i<n;i++)
	{
		sha256_w[i]=0;
		for(j=0;j<4;j++)
		{
			sha256_w[i]<<=8;
			sha256_w[i]+=*pTmp;
			pTmp++;
		}
	}

}
/***********************************************************************************************
* 函数名称：void sha256_ClearW()
* 功    能：清除工作暂存器区
***********************************************************************************************/
void sha256_ClearW()
{
	unsigned char i;
	
	for(i=0;i<64;i++)
	{
		sha256_w[i]=0x00000000;
	}
}

/***********************************************************************************************
* 函数名称：void sha256_ProChunk()
* 功    能：处理一个数据块（512位）
***********************************************************************************************/
void sha256_ProChunk()
{
	short i;
	unsigned long t1,t2;
	
	//步骤一
	for(i=0;i<64;i++)
	{
		if(0<=i&&i<=15)
		{
		}
		if(16<=i&&i<=63)
		{
			sha256_w[i]=Q1(sha256_w[i-2])+sha256_w[i-7]+Q0(sha256_w[i-15])+sha256_w[i-16];
		}    
	}
	
	//步骤二
	sha256_a=sha256_hh[0];
	sha256_b=sha256_hh[1];
	sha256_c=sha256_hh[2];
	sha256_d=sha256_hh[3];
	sha256_e=sha256_hh[4];
	sha256_f=sha256_hh[5];
	sha256_g=sha256_hh[6];
	sha256_h=sha256_hh[7];
	
	//步骤三
	for(i=0;i<64;i++)
	{
		t1=sha256_h+E1(sha256_e)+CH(sha256_e,sha256_f,sha256_g)+sha256_K[i]+sha256_w[i];
		t2=E0(sha256_a)+MAJ(sha256_a,sha256_b,sha256_c);
		sha256_h=sha256_g;
		sha256_g=sha256_f;
		sha256_f=sha256_e;
		sha256_e=sha256_d+t1;
		sha256_d=sha256_c;
		sha256_c=sha256_b;
		sha256_b=sha256_a;
		sha256_a=t1+t2;
	}
	
	//步骤四
	sha256_hh[0] += sha256_a;
	sha256_hh[1] += sha256_b;
	sha256_hh[2] += sha256_c;
	sha256_hh[3] += sha256_d;
	sha256_hh[4] += sha256_e;
	sha256_hh[5] += sha256_f;
	sha256_hh[6] += sha256_g;
	sha256_hh[7] += sha256_h;
}

/***********************************************************************************************
* 函数名称：void sha256_Display()
* 功    能：输出sha256码
***********************************************************************************************/
void sha256_Display()
{
//	printf("%0lx%0lx%0lx%0lx%0lx%0lx%0lx%0lx\n",sha256_hh[0],sha256_hh[1],sha256_hh[2],sha256_hh[3],sha256_hh[4],sha256_hh[5],sha256_hh[6],sha256_hh[7]);    
}

/***********************************************************************************************
* 函数名称：void sha256(unsigned char* ptr)
* 功    能：计算给定的字符串的sha256值
* 参    数：字符串
***********************************************************************************************/
void SHA256_Test(unsigned char* ptr)//因为是非标版，所以输入必须为8字节的倍数
{
	unsigned char* pTmp;
	unsigned long len,len1;//len--待处理的字符串长度;len1--字符串的长度
	unsigned char m,n;
	
	pTmp=ptr;
	
	//sha256码初始化
	sha256_hh[0] = 0x6a09e667;
	sha256_hh[1] = 0xbb67ae85;
	sha256_hh[2] = 0x3c6ef372;
	sha256_hh[3] = 0xa54ff53a;
	sha256_hh[4] = 0x510e527f;
	sha256_hh[5] = 0x9b05688c;
	sha256_hh[6] = 0x1f83d9ab;
	sha256_hh[7] = 0x5be0cd19;
	
	len=sha256_GetStrLen(pTmp);//获取长度
	len1=len;

	//段0：处理不需要补位的数据块
	while(len/64)
	{
		sha256_ClearW();//工作暂存区清零，w[16..63]的值不为零的话会发生错误。
		sha256_ByteToWord(pTmp,64);//将一个64字节的数据块转换为16个字并存入工作暂存器w[0..15]。
		sha256_ProChunk();//数据块处理
		pTmp+=64;//指针指向下一个数据块
		len-=64;//待处理的字符串长度减64
	}	
	//段0结束
	
	m=len/4;
	n=len%4;
	sha256_ClearW();
	sha256_ByteToWord(pTmp,m);
	switch(n)
	{
		case 0:
			sha256_w[m]=0x80000000;
		break;
		case 1:
			sha256_w[m]=*pTmp;
			sha256_w[m]<<=24;
			sha256_w[m]|=0x00800000;
		break;
		case 2:
			sha256_w[m]=*pTmp;
			sha256_w[m]<<=8;
			pTmp++;
			sha256_w[m]+=*pTmp;
			sha256_w[m]<<=16;
			sha256_w[m]|=0x00008000;
		case 3:
			sha256_w[m]=*pTmp;
			sha256_w[m]<<=8;
			pTmp++;
			sha256_w[m]+=*pTmp;
			sha256_w[m]<<=8;
			pTmp++;
			sha256_w[m]+=*pTmp;
			sha256_w[m]<<=8;
			sha256_w[m]|=0x00000080;
		default:;    
	}
	
	if((len1%64)>=56)
	{
		sha256_ProChunk();
		sha256_ClearW();    
	}
	
	sha256_AddBitLen(len1*8);
	sha256_ProChunk();
	
	sha256_Display();//结果输出
}
