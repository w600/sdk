/***********************************************************************/
/*  This file is part of the ARM Toolchain package                     */
/*  Copyright (c) 2010 Keil - An ARM Company. All rights reserved.     */
/***********************************************************************/
/*                                                                     */
/*  FlashDev.C:  Device Description for New Device Flash               */
/*                                                                     */
/***********************************************************************/

#include "..\FlashOS.H"        // FlashOS Structures


struct FlashDevice const FlashDevice  =  {
   FLASH_DRV_VERS,             // Driver Version, do not modify!
   "Winner Micro 1M Flash", // Device Name 
   ONCHIP,                     // Device Type
   0x08000000,                 // Device Start Address
   0x00100000,                 // Device Size in Bytes (1MB)
   256,                        // Programming Page Size
   0,                          // Reserved, must be 0
   0xFF,                       // Initial Content of Erased Memory
   20000,                       // Program Page Timeout 1000 mSec
   3000,                       // Erase Sector Timeout 3000 mSec

// Specify Size and Address of Sectors
   0x001000, 0x000000,         // Sector Size  4kB (256 Sectors)   
   SECTOR_END
};
