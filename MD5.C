/***********************************************************************************************
* 作    者：曾光辉
* 说    明：本程序实现的是一种非规范md5算法。它不规范的地方在于有：
*           1.字符串的bit长度是8的整数倍，而不是任意的。2.字符串的bit长度被限制在0~65535之间。
***********************************************************************************************/
#include<stddef.h>
#include<stdio.h>
#include <string.h>

/*md5转换用到的常量，算法本身规定的*/
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* 循环左移 */
#define ROTATE_LEFT(md5_x, n) (((md5_x) << (n)) | ((md5_x) >> (32-(n))))

// 全局变量
unsigned long  md5_x[16];/*分组暂存区*/
unsigned long  md5_a,md5_b,md5_c,md5_d;/*中间变量*/
unsigned long  md5_data[4];/*md5码*/

/***********************************************************************************************
* 函数功能：md5算法定义的函数
***********************************************************************************************/
unsigned long f(unsigned long md5_x,unsigned long y,unsigned long z)
{
	return (md5_x&y)|((~md5_x)&z);
}

unsigned long g(unsigned long md5_x,unsigned long y,unsigned long z)
{
	return (md5_x&z)|(y&(~z));
}

unsigned long h(unsigned long md5_x,unsigned long y,unsigned long z)
{
	return md5_x^y^z;
}

unsigned long i(unsigned long md5_x,unsigned long y,unsigned long z)
{
	return y^(md5_x|(~z));
}

// 第一轮运算函数
void ff(unsigned long md5_x,unsigned long s,unsigned long ac)
{
	if(s==S11||s==S21||s==S31||s==S41)
	{
		md5_a+=f(md5_b,md5_c,md5_d)+md5_x+ac;
		md5_a=ROTATE_LEFT(md5_a,s);
		md5_a+=md5_b;
	}
	if(s==S12||s==S22||s==S32||s==S42)
	{
		md5_d+=f(md5_a,md5_b,md5_c)+md5_x+ac;
		md5_d=ROTATE_LEFT(md5_d,s);
		md5_d+=md5_a;
	}        
	if(s==S13||s==S23||s==S33||s==S43)
	{
		md5_c+=f(md5_d,md5_a,md5_b)+md5_x+ac;
		md5_c=ROTATE_LEFT(md5_c,s);
		md5_c+=md5_d;
	}        
	if(s==S14||s==S24||s==S34||s==S44)
	{
		md5_b+=f(md5_c,md5_d,md5_a)+md5_x+ac;
		md5_b=ROTATE_LEFT(md5_b,s);
		md5_b+=md5_c;
	}            
}

// 第二轮运算函数
void gg(unsigned long md5_x,unsigned long s,unsigned long ac)
{
	if(s==S11||s==S21||s==S31||s==S41)
	{
		md5_a+=g(md5_b,md5_c,md5_d)+md5_x+ac;
		md5_a=ROTATE_LEFT(md5_a,s);
		md5_a+=md5_b;
	}
	if(s==S12||s==S22||s==S32||s==S42)
	{
		md5_d+=g(md5_a,md5_b,md5_c)+md5_x+ac;
		md5_d=ROTATE_LEFT(md5_d,s);
		md5_d+=md5_a;
	}        
	if(s==S13||s==S23||s==S33||s==S43)
	{
		md5_c+=g(md5_d,md5_a,md5_b)+md5_x+ac;
		md5_c=ROTATE_LEFT(md5_c,s);
		md5_c+=md5_d;
	}        
	if(s==S14||s==S24||s==S34||s==S44)
	{
		md5_b+=g(md5_c,md5_d,md5_a)+md5_x+ac;
		md5_b=ROTATE_LEFT(md5_b,s);
		md5_b+=md5_c;
	}
}

// 第三轮运算函数
void hh(unsigned long md5_x,unsigned long s,unsigned long ac)
{
	if(s==S11||s==S21||s==S31||s==S41)
	{
		md5_a+=h(md5_b,md5_c,md5_d)+md5_x+ac;
		md5_a=ROTATE_LEFT(md5_a,s);
		md5_a+=md5_b;
	}
	if(s==S12||s==S22||s==S32||s==S42)
	{
		md5_d+=h(md5_a,md5_b,md5_c)+md5_x+ac;
		md5_d=ROTATE_LEFT(md5_d,s);
		md5_d+=md5_a;
	}        
	if(s==S13||s==S23||s==S33||s==S43)
	{
		md5_c+=h(md5_d,md5_a,md5_b)+md5_x+ac;
		md5_c=ROTATE_LEFT(md5_c,s);
		md5_c+=md5_d;
	}        
	if(s==S14||s==S24||s==S34||s==S44)
	{
		md5_b+=h(md5_c,md5_d,md5_a)+md5_x+ac;
		md5_b=ROTATE_LEFT(md5_b,s);
		md5_b+=md5_c;
	}
}

// 第四轮运算函数
void ii(unsigned long md5_x,unsigned long s,unsigned long ac)
{
	if(s==S11||s==S21||s==S31||s==S41)
	{
		md5_a+=i(md5_b,md5_c,md5_d)+md5_x+ac;
		md5_a=ROTATE_LEFT(md5_a,s);
		md5_a+=md5_b;
	}
	if(s==S12||s==S22||s==S32||s==S42)
	{
		md5_d+=i(md5_a,md5_b,md5_c)+md5_x+ac;
		md5_d=ROTATE_LEFT(md5_d,s);
		md5_d+=md5_a;
	}        
	if(s==S13||s==S23||s==S33||s==S43)
	{
		md5_c+=i(md5_d,md5_a,md5_b)+md5_x+ac;
		md5_c=ROTATE_LEFT(md5_c,s);
		md5_c+=md5_d;
	}        
	if(s==S14||s==S24||s==S34||s==S44)
	{
		md5_b+=i(md5_c,md5_d,md5_a)+md5_x+ac;
		md5_b=ROTATE_LEFT(md5_b,s);
		md5_b+=md5_c;
	}
}

/***********************************************************************************************
* 函数名称：unsigned long GetStrLen()
* 函数功能：获取字符串的长度
* 入口参数：ptr--字符串指针
* 出口参数：len--32位的返回值
* 说    明：原md5算法要求存储字符串长度的变量为64位，即8个字节。这里只用了4个字节，根据应用场合
*           的不同修改相应的变量定义及函数md5()中对x[14]md5_x[15]的赋值语句即可。
***********************************************************************************************/
unsigned long GetStrLen(unsigned char * ptr)
{
	unsigned long len=0;
	unsigned char * pTmp;
	
	pTmp=ptr;
	while(pTmp!=NULL&&(*pTmp)!='\0')
	{
		len++;
		pTmp++;
	}
	return len;
}

/***********************************************************************************************
* 函数名称：void ByteToWord()
* 函数功能：将指定8位字符串整合为一个个32位的字，存入分组暂存器x[]中，字的个数由用户指定
* 入口参数：*ptr--8位字符串指针    n--指定的字的个数
* 出口参数：全局x[]
* 说    明：用户需在调用此函数之前先获得字符串的长度，然后再确定有效的“n”值。例如，当字符串
*           长度为7时，不能指定n为2或更大的数，即不能这样调用 ByteToWord(ptr,2)。
***********************************************************************************************/
void ByteToWord(unsigned char * ptr,unsigned char n)
{
	unsigned char  i,j;
	unsigned char * pTmp;
	unsigned long tmp;
	
	pTmp=ptr;
	
	for(i=0;i<n;i++)
	{
		md5_x[i]=0x00000000;
		tmp = 0;
		for(j=0;j<4;j++)
		{
			tmp>>=8;
			tmp +=*pTmp<<24;
			pTmp++;
		}
		md5_x[i] = tmp;
	}
}

/***********************************************************************************************
* 函数名称：void md5_Print()
* 函数功能：输出md5的结果
***********************************************************************************************/
void md5_Print()
{
//	unsigned char i;
//	
//	for(i=0;i<4;i++)
//	{
//		printf("%02bx",(unsigned char)md5_data[i]);
//		printf("%02bx",(unsigned char)(md5_data[i]>>8));
//		printf("%02bx",(unsigned char)(md5_data[i]>>16));
//		printf("%02bx",(unsigned char)(md5_data[i]>>24));
//	}
}

/***********************************************************************************************
* 函数名称：void md5_ProChunk()
* 函数功能：md5分组处理
***********************************************************************************************/
void md5_ProChunk()
{
	md5_a=md5_data[0];
	md5_b=md5_data[1];
	md5_c=md5_data[2];
	md5_d=md5_data[3];
	
	/* 第一轮运算 */
	ff(md5_x[ 0], S11, 0xd76aa478); /* 1 */
	ff(md5_x[ 1], S12, 0xe8c7b756); /* 2 */
	ff(md5_x[ 2], S13, 0x242070db); /* 3 */
	ff(md5_x[ 3], S14, 0xc1bdceee); /* 4 */
	ff(md5_x[ 4], S11, 0xf57c0faf); /* 5 */
	ff(md5_x[ 5], S12, 0x4787c62a); /* 6 */
	ff(md5_x[ 6], S13, 0xa8304613); /* 7 */
	ff(md5_x[ 7], S14, 0xfd469501); /* 8 */
	ff(md5_x[ 8], S11, 0x698098d8); /* 9 */
	ff(md5_x[ 9], S12, 0x8b44f7af); /* 10 */
	ff(md5_x[10], S13, 0xffff5bb1); /* 11 */
	ff(md5_x[11], S14, 0x895cd7be); /* 12 */
	ff(md5_x[12], S11, 0x6b901122); /* 13 */
	ff(md5_x[13], S12, 0xfd987193); /* 14 */
	ff(md5_x[14], S13, 0xa679438e); /* 15 */
	ff(md5_x[15], S14, 0x49b40821); /* 16 */
	
	/* 第二轮运算 */
	gg(md5_x[ 1], S21, 0xf61e2562); /* 17 */
	gg(md5_x[ 6], S22, 0xc040b340); /* 18 */
	gg(md5_x[11], S23, 0x265e5a51); /* 19 */
	gg(md5_x[ 0], S24, 0xe9b6c7aa); /* 20 */
	gg(md5_x[ 5], S21, 0xd62f105d); /* 21 */
	gg(md5_x[10], S22,  0x2441453); /* 22 */
	gg(md5_x[15], S23, 0xd8a1e681); /* 23 */
	gg(md5_x[ 4], S24, 0xe7d3fbc8); /* 24 */
	gg(md5_x[ 9], S21, 0x21e1cde6); /* 25 */
	gg(md5_x[14], S22, 0xc33707d6); /* 26 */
	gg(md5_x[ 3], S23, 0xf4d50d87); /* 27 */
	gg(md5_x[ 8], S24, 0x455a14ed); /* 28 */
	gg(md5_x[13], S21, 0xa9e3e905); /* 29 */
	gg(md5_x[ 2], S22, 0xfcefa3f8); /* 30 */
	gg(md5_x[ 7], S23, 0x676f02d9); /* 31 */
	gg(md5_x[12], S24, 0x8d2a4c8a); /* 32 */
	
	/* 第三轮运算 */
	hh(md5_x[ 5], S31, 0xfffa3942); /* 33 */
	hh(md5_x[ 8], S32, 0x8771f681); /* 34 */
	hh(md5_x[11], S33, 0x6d9d6122); /* 35 */
	hh(md5_x[14], S34, 0xfde5380c); /* 36 */
	hh(md5_x[ 1], S31, 0xa4beea44); /* 37 */
	hh(md5_x[ 4], S32, 0x4bdecfa9); /* 38 */
	hh(md5_x[ 7], S33, 0xf6bb4b60); /* 39 */
	hh(md5_x[10], S34, 0xbebfbc70); /* 40 */
	hh(md5_x[13], S31, 0x289b7ec6); /* 41 */
	hh(md5_x[ 0], S32, 0xeaa127fa); /* 42 */
	hh(md5_x[ 3], S33, 0xd4ef3085); /* 43 */
	hh(md5_x[ 6], S34,  0x4881d05); /* 44 */
	hh(md5_x[ 9], S31, 0xd9d4d039); /* 45 */
	hh(md5_x[12], S32, 0xe6db99e5); /* 46 */
	hh(md5_x[15], S33, 0x1fa27cf8); /* 47 */ 
	hh(md5_x[ 2], S34, 0xc4ac5665); /*48 */
	
	/* 第四轮运算 */
	ii(md5_x[ 0], S41, 0xf4292244); /* 49 */
	ii(md5_x[ 7], S42, 0x432aff97); /* 50 */
	ii(md5_x[14], S43, 0xab9423a7); /* 51 */
	ii(md5_x[ 5], S44, 0xfc93a039); /* 52 */
	ii(md5_x[12], S41, 0x655b59c3); /* 53 */
	ii(md5_x[ 3], S42, 0x8f0ccc92); /* 54 */
	ii(md5_x[10], S43, 0xffeff47d); /* 55 */
	ii(md5_x[ 1], S44, 0x85845dd1); /* 56 */
	ii(md5_x[ 8], S41, 0x6fa87e4f); /* 57 */
	ii(md5_x[15], S42, 0xfe2ce6e0); /* 58 */
	ii(md5_x[ 6], S43, 0xa3014314); /* 59 */
	ii(md5_x[13], S44, 0x4e0811a1); /* 60 */
	ii(md5_x[ 4], S41, 0xf7537e82); /* 61 */
	ii(md5_x[11], S42, 0xbd3af235); /* 62 */
	ii(md5_x[ 2], S43, 0x2ad7d2bb); /* 63 */
	ii(md5_x[ 9], S44, 0xeb86d391); /* 64 */
	
	md5_data[0] += md5_a;
	md5_data[1] += md5_b;
	md5_data[2] += md5_c;
	md5_data[3] += md5_d;
}

/***********************************************************************************************
* 函数名称：void md5(unsigned char* ptr)
* 函数功能：计算md5
***********************************************************************************************/
void MD5_Test(unsigned char* ptr)//因为是非标版，所以输入必须为8字节的倍数
{
	unsigned long  len, len1;
	unsigned char * pTmp;
	unsigned char  n,m;
	
	pTmp=ptr;
	len=strlen((char*)(pTmp));//获取字符串长度
	len1=len;
	
	md5_data[0]=0x67452301;
	md5_data[1]=0xefcdab89;
	md5_data[2]=0x98badcfe;
	md5_data[3]=0x10325476;
	
	// 功能0：处理不需要补位的完整分组
	while((len/64)>0)
	{  
		memset(md5_x,0x00,sizeof(md5_x));//由于ByteToWord()用的是循环移位，如果不清零x[]的话可能会产生错误，所以此处要清零
		ByteToWord(pTmp,16);//将分组转换到x[]中
		md5_ProChunk();//分组处理
		len-=64;//处理完一个分组后，未进行处理的分组长度要减去64 Byte(512 bit)
		pTmp+=64;//指向下一个分组
	}
	// 功能0
	
	// 功能1：处理需要进行补位的分组
	memset(md5_x,0x00,sizeof(md5_x));//将分组暂存器x[]清零
	ByteToWord(pTmp,len/4);//字符串转换成字存入x[]
	
	// 功能1.0 将多余的字节组合进下一个字并进行补位后存入x[]
	n=len%4;
	m=len/4;
	switch(n)
	{
		case 0:
			md5_x[m]=md5_x[m]|0x00000080;//多余0字节的情况
		break;
		case 1:
			md5_x[m]=*pTmp;
			md5_x[m]=md5_x[m]|0x00008000;//多余1字节的情况
		break;
		case 2:
			md5_x[m]=*(pTmp+1);
			md5_x[m]=md5_x[m]<<8;
			md5_x[m]=md5_x[m]+(*pTmp);
			md5_x[m]=md5_x[m]|0x00800000;//多余2字节的情况
		break;
		case 3:
			md5_x[m]=*(pTmp+2);
			md5_x[m]=md5_x[m]<<8;
			md5_x[m]=md5_x[m]+*(pTmp+1);
			md5_x[m]=md5_x[m]<<8;
			md5_x[m]=md5_x[m]+(*pTmp);
			md5_x[m]=md5_x[m]|0x80000000;//多余3字节的情况
		default:;
	}
	// 功能1.0
	
	if(len>=56)//当此分组的长度大于等于56时需多处理一个分组
	{
		md5_ProChunk();
		memset(md5_x,0x00,sizeof(md5_x));
	}
	
	md5_x[14]=len1*8;//添加字符串‘位’长度信息
	//md5_x[15]..
	md5_ProChunk();
	// 功能1
	
	md5_Print();//输出结果
}
