/******************************************************************************/
/* RETARGET.C: 'Retarget' layer for target-dependent low level functions      */
/******************************************************************************/

#include <stdio.h>
#include <rt_misc.h>

#if (GCC_COMPILE!=1)
//#pragma import(__use_no_semihosting_swi)

static unsigned int std_libspace[__USER_LIBSPACE_SIZE];

void *__user_libspace(void)
{
    return (void *)&std_libspace;
}

extern int sendchar(int ch);

struct __FILE { int handle; /* Add whatever you need here */ };
FILE __stdout;
FILE __stdin;

int fputc(int ch, FILE *f) 
{
  return (sendchar(ch));
}


int ferror(FILE *f) 
{
  /* Your implementation of ferror */
  return EOF;
}

void _ttywrch(int ch) 
{
  sendchar(ch);
}

void _sys_exit(int return_code) 
{
label:  
	goto label;  /* endless loop */
}

#endif
