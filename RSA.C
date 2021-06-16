#include <stdio.h>

unsigned long candp(unsigned long a,unsigned long b,unsigned long c)
{
	unsigned long r=1;

	b = b+1;
	while(b!=1)
	{
		r = r*a;
		r = r%c;
		b--;
	}
	return r;
}

unsigned long RSA_Key[3]=
{
	17,7,5	//做运算之前先要设置好密钥，这里只是设置密钥的DEMO。
};

unsigned char RSA_Test(unsigned long Source, unsigned long Target, unsigned char mode)
{
	unsigned long d,n,t,tt;
	unsigned long p,q,e;
	Target = Target;

	p =	RSA_Key[0];
	q =	RSA_Key[1];
	e = RSA_Key[2];

	n = p*q;
	t = (p-1)*(q-1);

	if(e<1 || e>t)
	{
		return 0;
	}

	switch(mode)
	{
		case 1:
			Target = candp(Source,e,n);//Source为要加密的明文数字
		break;
		case 2://这里可能会产生特别大的数据量需要生成大素数及大数取模，很耗费时间，生成复杂密钥时可能不止十分钟，所以解密时还是尽量让PC来做吧
			d = 0;
			do{
			    d++;
				tt = (e*d)%t;
			}while(tt!=1);
			Target = candp(Source,d,n);//Source为要解密的密文数字
		break;
	}
	return 1;
}
