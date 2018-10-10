#if GCC_COMPILE
#include <stdio.h>
#include <stdlib.h>
#include <reent.h>
#include <string.h>
#include <stdarg.h>
#define HR_UART0_INT_MASK           (0x40010800 + 0x14)
#define HR_UART0_FIFO_STATUS        (0x40010800 + 0x1C)
#define HR_UART0_TX_WIN             (0x40010800 + 0x20)
typedef volatile unsigned int TLS_REG; 

static inline void wm_reg_write32(unsigned int reg, unsigned int val)
{
    *(TLS_REG *)reg = val;
}

static inline unsigned int wm_reg_read32(unsigned int reg)
{
    unsigned int val = *(TLS_REG *)reg;
    return val;
}

int sendchar(int ch)
{
	wm_reg_write32(HR_UART0_INT_MASK, 0x3);
    if(ch == '\n')  
	{
		while (wm_reg_read32(HR_UART0_FIFO_STATUS) & 0x3F);
		wm_reg_write32(HR_UART0_TX_WIN, '\r');
    }
    while(wm_reg_read32(HR_UART0_FIFO_STATUS) & 0x3F);
    wm_reg_write32(HR_UART0_TX_WIN, (char)ch);
    wm_reg_write32(HR_UART0_INT_MASK, 0x0);
    return ch;
}


//function:	将数据转换成字符串
//paramter:
//str	:	转换之后存在此buffer
//num	:	要转换的数据
//base	:	十进制，十六进制
//width	:	对齐宽度
//opflag :	操作符，bit定义如下

#define	P_ALIGN_BIT	(0x01<<0)	// bit=1 左对齐 bit=0右对齐
#define  P_FILL_BIT		(0x01<<1)	//bit = 1填充'0'，否则填充' '
#define  P_BIG_BIT		(0x01<<2)	//bit=1，大写，否则小写

int Int2Str(char *str,int num,char base,char width,int opflag) 
{   
	char temp; 
	int len = 0;
	signed char k = 0;
	char *str_bk;
	signed char k_bk;

	if(num <0) 
	{ 
		num = -num;   
		*str='-';
		str++;
		len++;  
	}
	if(0 == num)
	{
		*str = '0';
		str ++;
		k ++;
	}
	while(num) 
	{	
		temp= num%base; 
		if(temp > 9) // insert hexdecimal--ABCDEF-- 
		{  
			temp-=10;  
			if(opflag & P_BIG_BIT)
				*str = temp + 'A';  	
			else
				*str = temp + 'a';  
		} 
		else 
		{  
			*str = temp + '0'; 
		}
		num=num/base; 
		str++;
		k++; 
	}  

	if(opflag&P_ALIGN_BIT)	//左对齐
	{
		str_bk = str;
		k_bk = k;		//先备份指针和长度，倒序之后继续
		str --;
		k --;
		while(k>0) 
		{
			temp = *str; 
			*str = *(str-k); 
			*(str-k) = temp; 
			str--; 
			k-=2; 
		}  
		k = k_bk;
		str = str_bk;
	}	
 
	//不足宽度的用' '补齐
	while(width>k) 
	{  
		if(opflag&P_FILL_BIT)
		{
			*str++ ='0';
		}
		else
		{
			*str++ =' ';
		}
		k++; 
	}

	len=len+k; 
	*str-- = '\0'; 
	k--; 
 	if(0 == (opflag&P_ALIGN_BIT))	//右对齐
 	{
		//倒序
		while(k>0) 
		{
			temp = *str; 
			*str = *(str-k); 
			*(str-k) = temp; 
			str--; 
			k-=2; 
		}  
 	} 
	return len; 
}  


int wm_vprintf(const char *fmt, va_list arg_ptr)
{
	unsigned char width=0; 	//保留宽度
	unsigned int len; 			//数据宽度
	char *fp = fmt;  
	//va_list arg_ptr; 
	char *pval;
	int opflag = 0;
	char store[20];
	char c;
	int i;
	char* str;
	
	//va_start(arg_ptr, fmt); //arg_ptr 指向第一个参数
	while (*fp !='\0') 
	{
		c = *fp++; 
		if (c != '%') 
		{
			sendchar(c);
		} 
		else 
		{ 
			width = 0;  //获取数据宽度
			opflag = 0;
			if('-' == *fp)
			{
				opflag |= P_ALIGN_BIT;//左对齐
				fp ++;
			}
			if('0' == *fp)	//前面补零
			{
				opflag |= P_FILL_BIT;	//补零
				fp ++;
			}

			while(*fp>='0'&&*fp<='9') 
			{  
				width = width * 10 + (*fp) - '0'; 
				fp++; 
			} 
			if('.' == *fp)	//浮点运算暂时没用，不处理
			{
				fp ++;
				while(*fp>='0'&&*fp<='9') 
				{  
					fp++; 
				}
			}

			while('l' == *fp)
			{
				fp ++;
			}			
			
			switch (*fp) 
			{  
				case 'c': 
				case 'C': 
					c = (char)va_arg(arg_ptr, int);
			             sendchar(c);
					break; 
				case 'd': 
				case 'i':  
				case 'u':	
			              i = va_arg(arg_ptr, int);
			              str = store;
					Int2Str(store,i,10,width,opflag); 
      		                    while( *str != '\0') sendchar(*str++);
					break; 
				case 'x': 
				case 'X':  
			              i = va_arg(arg_ptr, int);
			              str = store;
					if('X' == *fp)
					{
						opflag |= P_BIG_BIT;
					}					 
					 Int2Str(store,i,16,width,opflag); 		   
			                while( *str != '\0') sendchar(*str++);
					break; 
				case 'o':
			             i = va_arg(arg_ptr, int);
			             str = store;
					Int2Str(store,i,8,width,opflag); 		   
       			      while( *str != '\0') sendchar(*str++);
					break;
				case 's': 
				case 'S':
					pval=va_arg(arg_ptr,char*);
					len = strlen(pval);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							sendchar(' ');
						}
					}
                                for(i=0;i < len;i++)
                                {
						sendchar(pval[i]);					
                                }
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							sendchar(' ');
						}
					}
					break; 
				case '%':  
					sendchar('%');
					break; 
				default: 
					break; 
			}
			fp++; 
		} 
	}  
	//va_end(arg_ptr); 
	return 0; 
	
}

int wm_printf(const char *fmt,...) 
{
	va_list ap;

	va_start(ap, fmt);
	wm_vprintf(fmt,ap);
	va_end(ap);
}


int wm_sprintf(char *str, const char *fmt,...)
{ 
	unsigned int num = 0; 	//最后返回的长度
	unsigned char width=0; 	//保留宽度
	unsigned int len; 			//数据宽度
	char *fp = fmt;  
	va_list arg_ptr; 
	int arg_num; 
	char *pval;
	int i;
	int opflag = 0;
	char c;
	
	va_start(arg_ptr, fmt); //arg_ptr 指向第一个参数
	while (*fp !='\0') 
	{
		c = *fp++; 
		if (c != '%') 
		{
			*str++ = c; 
			num++; 
		} 
		else 
		{ 
			width = 0;  //获取要保留几位数
			opflag = 0;
			if('-' == *fp)
			{
				opflag |= P_ALIGN_BIT;//左对齐
				fp ++;
			}
			if('0' == *fp)	//前面补零
			{
				opflag |= P_FILL_BIT;	//补零
				fp ++;
			}

			while(*fp>='0'&&*fp<='9') 
			{  
				width = width * 10 + (*fp) - '0'; 
				fp++; 
			} 
			if('.' == *fp)	//浮点运算暂时没用，不处理
			{
				fp ++;
				while(*fp>='0'&&*fp<='9') 
				{  
					fp++; 
				}
			}
			while('l' == *fp)
			{
				fp ++;
			}			
			
			switch (*fp) 
			{  
				case 'c': 
				case 'C': 
					arg_num = va_arg(arg_ptr, int); 
					*str++ = (char)arg_num;
					num ++;
					break; 
				case 'd': 
				case 'i':  
				case 'u':	
					arg_num = va_arg(arg_ptr, int); 
					len = Int2Str(str,arg_num,10,width,opflag); 
					str+=len;num+=len; 
					break; 
				case 'x': 
				case 'X':  
					if('X' == *fp)
					{
						opflag |= P_BIG_BIT;
					}
					arg_num = va_arg(arg_ptr, int);  
					len = Int2Str(str,arg_num,16,width,opflag); 
					str+=len;num+=len; 
					break; 
				case 'o':
					arg_num = va_arg(arg_ptr, int);  
					len = Int2Str(str,arg_num,8,width,opflag); 	
					str+=len;num+=len; 	
					break;
				case 's': 
				case 'S':
					pval=va_arg(arg_ptr,char *);
					len = strlen(pval);
					if((width > len) && (0 == (opflag&P_ALIGN_BIT)))		//右对齐
					{
						for(i = 0;i < (width - len);i ++)	//左边补空格
						{
							*str ++ = ' ';
							num ++;
						}
					}
                                for(i=0;i < len;i++)
                                {
                                        *str++=pval[i];
                                }
					num +=len;
					if((width > len) && (opflag&P_ALIGN_BIT))		//左对齐
					{
						for(i = 0;i < (width - len);i ++)	//右边补空格
						{
							*str ++ = ' ';
							num ++;
						}
					}
					break; 
				case '%':  
					*str++ = '%'; 
					num ++;
					break; 
				default: 
					break; 
			}
			fp++; 
		} 
	}  
 
	*str = '\0';  
	va_end(arg_ptr); 
	return num; 
}

_ssize_t _write_r (struct _reent *r, int file, const void *ptr, size_t len)
{
	size_t i;
	char *p;
	
	p = (char*) ptr;
	
	for (i = 0; i < len; i++) 
	{
#if 0
		if (*p == '\n') 
		{
			sendchar('\r');
		}
#endif		
		sendchar(*p++);
	}
	return len;
}

_ssize_t _read_r(struct _reent *r, int file, void *ptr, size_t len)
{
	return 0;
}

int _close_r(struct _reent *r, int file)
{
	return 0;
}

_off_t _lseek_r(struct _reent *r, int file, _off_t ptr, int dir)
{
	return (_off_t)0;	/*  Always indicate we are at file beginning.  */
}

int _fstat_r(struct _reent *r, int file, struct stat *st)
{
	return 0;
}

int _isatty(int file)
{
	return 1;
}

void abort(void)
{
  while(1);
}

extern char end[];
//extern char __StackLimit[];
extern char __HeapLimit[];
static char *heap_ptr = end;
//static char *heap_end = __StackLimit;
static char *heap_end = __HeapLimit;

void * _sbrk_r(struct _reent *_s_r, ptrdiff_t nbytes)
{
	char *base;

	base = heap_ptr;

	if(base + nbytes > heap_end)
    {
    	wm_printf("kevin debug heap err = %x, %x\r\n", (int)heap_ptr, (int)nbytes);
		return (void *)-1;
    }
	
	heap_ptr += nbytes;	
	return base;
}

void * tls_reserve_mem_lock(int nbytes)
{
	if(heap_end - (nbytes + 4) <= heap_ptr)
	{
		return NULL;
	}
	heap_end  -= (nbytes + 4);
	return (void *)((((int)heap_end + 3) >> 2) << 2);	
}

void tls_reserve_mem_unlock(void)
{	
	heap_end = __HeapLimit;
}

void print_heap_status(void)
{
	wm_printf("kevin debug heap %d KB\r\n", (int)(heap_end - heap_ptr)/1024);
}
#endif
