@  Copyright ARM Ltd 2002-2008. All rights reserved.
@
@  This code provides basic initialization for an ARM946E-S including:
@
@  - creation of memory protection regions
@  - setting of region attributes
@
@  - enabling the Instruction and Data caches and Write buffer
@  - enabling Memory Protection Unit
@  - regions must be defined for TCM memory addresses
@
@  This code must be run from a privileged mode

@@  MPU region size defines

.equ Region_4K,0b01011
.equ Region_8K,0b01100
.equ Region_16K,0b01101
.equ Region_32K     , 0b01110
.equ Region_64K     , 0b01111
.equ Region_128K    , 0b10000
.equ Region_256K    , 0b10001
.equ Region_512K    , 0b10010
.equ Region_1M      , 0b10011
.equ Region_2M      , 0b10100
.equ Region_4M      , 0b10101
.equ Region_8M      , 0b10110
.equ Region_16M     , 0b10111
.equ Region_32M     , 0b11000
.equ Region_64M     , 0b11001
.equ Region_128M    , 0b11010
.equ Region_256M    , 0b11011
.equ Region_512M    , 0b11100
.equ Region_1G      , 0b11101
.equ Region_2G      , 0b11110
.equ Region_4G      , 0b11111

.equ Region_Enable  , 0b1


.section .text
.global Init_MPU
Init_MPU:
@ MPU region definitions/properties
@ =================================
@
@ Note each Instruction region must have a corresponding data region
@ so inline data accesses will work
@
@ Note each region base address must be a multiple of its size

@ 区域0       : 0   ~     4GB                      NCNB	             No  access
@ 区域1       : 0   ~     0x20000,   指令区(128K)       Cached NB		 Rea d only
@									 (debug 256)
@ 区域3       : 0x20000 ~ 0x60000    数据区(256K)        Cached Buffered    Full access





@ Set up region 0 - Background and enable
        MOV     r0,#(Region_4G << 1)|Region_Enable
        MCR     p15, 0, r0, c6, c0, 0

@ Set up region 1 - instrcture and enable

        MOV     r0,#(Region_128K <<1)|Region_Enable
        MCR     p15, 0, r0, c6, c1, 0

@ Set up region 3 - RAM and enable
        LDR     r0, = 0x20000|(Region_256K << 1)|Region_Enable
        MCR     p15, 0, r0, c6, c3, 0

@ Set up region 4 - DSRAM_SD and enable
@	    MOV     r0, #0x30000
@        LDR     r0, = 0x30000 :OR: (Region_32K <<1):OR:Region_Enable
@        MCR     p15, 0, r0, c6, c4, 0

@
@ Set up cacheable /bufferable attributes
      @  MOV     r0, #0b001000               @ cache bits set for SRAM and FLASH
       @ MCR     p15, 0, r0, c2, c0, 0       @ data cacheable

       @ MOV     r0, #0b000010               @ cache bits set for SRAM and FLASH
       @ MCR     p15, 0, r0, c2, c0, 1       @ instr cacheable

       @ MOV     r0, #0b001000               @ bufferable bit set for RAM
       @ MCR     p15, 0, r0, c3, c0, 0       @ sets Write Back Cacheing

@ Set up access permissions

        MOV     r0,#0b0011
		ORR     r0,r0,#(0b0110 << 4)        @ INS   set to P: RO,    U: RO
        ORR     r0,r0,#(0b0011 << 8)        @ RAM   set to P: RW     U: RW
        ORR     r0,r0,#(0b0011 << 12)       @ RAM   set to P: RW     U: RW
@
@ In this example the access permissions are the same for both instruction and data sides
@ Apply these to both instruction and data side
        MCR     p15, 0, r0, c5, c0, 2       @ data AP
        MCR     p15, 0, r0, c5, c0, 3       @ instr AP

@
@ Set global core configurations
@===============================
@
        MRC     p15, 0, r0, c1, c0, 0       @ read CP15 register 1
        BIC     r0, r0, #(0x1 <<12)         @ ensure I Cache disabled before MPU enable
        BIC     r0, r0, #(0x1 <<2)          @ enable D Cache disabled before MPU enable
        ORR     r0, r0, #0x1                @ enable MPU bit
        MCR     p15, 0, r0, c1, c0, 0       @ write cp15 register 1
        

@        MRC     p15, 0, r0, c1, c0, 0       @ read CP15 register 1
@        ORR     r0, r0, #(0x1  <<12)        @ enable I Cache
@        ORR     r0, r0, #(0x1  <<2)         @ enable D Cache
@        MCR     p15, 0, r0, c1, c0, 0       @ write CP15 register 1        

		MRC		p15, 0, r0, c2, c0, 0
		ORR		r0, r0, #(0x6)					@;region 1,2
		MCR		p15, 0, r0, c2, c0, 0 	 		@;enable data cachable bits
			
		MRC	  	p15, 0, r0, c2, c0, 1
		ORR	  	r0, r0, #(0xff)
		MCR	  	p15, 0, r0, c2, c0, 1 	 		@;enable Instruction cachable bits

	 	MRC     p15, 0, r0, c1, c0, 0       				@; read CP15 register 1
        	ORR     r0, r0, #(0x1  <<12)         			@; enable I Cache
        	ORR     r0, r0, #(0x1  <<2)          			@; enable D Cache
        	MCR     p15, 0, r0, c1, c0, 0       				@; write CP15 register 1
	
		MRC 	p15, 0, r0, c3, c0, 0
		ORR 	r0, r0, #(0xff)
		MCR 	p15, 0, r0, c3, c0, 0			@;enable data buffer bits


        .extern  main                      @ import label to __main
        BL       main                      @ branch to C Library entry

@       ENDFUNC
.end
