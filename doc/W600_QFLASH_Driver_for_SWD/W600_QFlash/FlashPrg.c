/***********************************************************************/
/*  This file is part of the ARM Toolchain package                     */
/*  Copyright (c) 2010 Keil - An ARM Company. All rights reserved.     */
/***********************************************************************/
/*                                                                     */
/*  FlashDev.C:  Flash Programming Functions adapted                   */
/*               for New Device 256kB Flash                            */
/*                                                                     */
/***********************************************************************/

#include "..\FlashOS.H"        // FlashOS Structures
#define FLASH_OLD_DRV_FTR   0
typedef volatile unsigned char		vu8;
typedef volatile unsigned short		vu16;
typedef volatile unsigned long		vu32;

#define M8(adr)		(*((vu8 *) (adr)))
#define M16(adr)	(*((vu16*) (adr)))
#define M32(adr)	(*((vu32*) (adr)))

#define FLASH_BASE      0x40002000

#define FLASH           ((FLASH_TypeDef*) FLASH_BASE)

// FLASH BANK size
#define BANK1_SIZE      0x00100000      // Bank1 Size = 1MB

unsigned long base_adr;


/*
 *  Initialize Flash Programming Functions
 *    Parameter:      adr:  Device Base Address
 *                    clk:  Clock Frequency (Hz)
 *                    fnc:  Function Code (1 - Erase, 2 - Program, 3 - Verify)
 *    Return Value:   0 - OK,  1 - Failed
 */

int Init (unsigned long adr, unsigned long clk, unsigned long fnc) {
  return (0);                                  // Finished without Errors
}


/*
 *  De-Initialize Flash Programming Functions
 *    Parameter:      fnc:  Function Code (1 - Erase, 2 - Program, 3 - Verify)
 *    Return Value:   0 - OK
 */

int UnInit (unsigned long fnc) {
  return (0);                                  // Finished without Errors
}


/*
 *  Erase complete Flash Memory
 *    Return Value:   0 - OK, 
 */

int EraseChip (void) {

  return (0);                                  // Finished without Errors
}


/*
 *  Erase Sector in Flash Memory
 *    Parameter:      adr:  Sector Address
 *    Return Value:  
 */

int EraseSector (unsigned long sectoradr) {
	/*Write Enable*/
	*(volatile unsigned int *)0x40002000 = 0x6;
	*(volatile unsigned int *)0x40002004 = 0x10000000;

	*(volatile unsigned int *)0x40002000 = 0x80000820;
	*(volatile unsigned int *)0x40002004 = 0x10000000|((sectoradr&0xFFFFF)<<8);

  return (0);                                  // Finished without Errors
}


/*
 *  Program Page in Flash Memory
 *    Parameter:      adr:  Page Start Address
 *                    sz:   Page Size
 *                    buf:  Page Data
 *    Return Value:   0 - OK,  1 - Failed
 */

int ProgramPage (unsigned long adr, unsigned long sz, unsigned char *buf) {
	
	unsigned long base_addr;
	unsigned long size = 0;

	base_addr = 0x40002200;
	size = sz;
	while(size)
	{
		M32(base_addr) = *((unsigned long *)buf);
		base_addr += 4;
		buf += 4;
		size -= 4;				
	}

	/*Write Enable*/
	*(volatile unsigned int *)0x40002000 = 0x6;
	*(volatile unsigned int *)0x40002004 = 0x10000000;

	*(volatile unsigned int *)0x40002000 = 0x80009002|(((sz-1)&0xFF)<<16);
	*(volatile unsigned int *)0x40002004 = 0x10000000|((adr&0xFFFFF)<<8);

	return (0);
}

