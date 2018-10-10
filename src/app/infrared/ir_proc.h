#ifndef IR_PROC_H
#define IR_PROC_H

/**********************************************************************************************************
* Description: 	
* The use of the process:
* 1 call IR_Learn_Start() to get the signal data; 
* 2 sent the signal data to the phone side for format conversion save; 
* 3 mobile phone side will send data to the module; 
* 4 module call IR_Sent_Start() to send the received data.
*
* Local testing process:
* 1 call IR_Learn_Start() to get the signal data; 
* 2 call Data_transfer() to convert the data; 
* 3 call IR_TestSent_Start() to send the converted signal data.
*
* GPIO13: use for IR output control
* GPIO14: the same as GPIO13
* GPIO11: use for IR input when learning
**********************************************************************************************************/




/**********************************************************************************************************
* Description: 	This function is used to send IR.
*
* Arguments  : 	Buf0					input, storage IR data obtained from the server through Wi-Fi.
*								Buf0_Lenth		input, the length of the data in buf0.
*               ir_tx_flag    input, whether GPIO14 outputs the same control signal as GPIO13. 1:output 0:no output
*
* Returns    :  
*
**********************************************************************************************************/
extern void IR_Sent_Start(unsigned char Buf0[], unsigned short Buf0_Lenth,bool ir_tx_flag);

/**********************************************************************************************************
* Description: 	This function is used to learn IR.
*
* Arguments  : 	Buf0		output, 9 bytes. The data length of Buf1 is Buf0[2]*256 + Buf0[1].
*								Buf1		output, store the data to learn, the length is uncertain, the actual length calculated according to buf0.
*                
* Returns    :  0x66    learn successful
*               0       did not receive the IR signal in 15 seconds , overtime to return
**********************************************************************************************************/
extern unsigned char  IR_Learn_Start(unsigned char Buf0[],unsigned char Buf1[]);//sucess return 0x66, return 0 if don't receive data over 15s

/**********************************************************************************************************
* Description: 	This function is used to test.
*
* Arguments  : 	Buf0_RX		input, corresponding to Buf0 in the IR_Learn_Start fuction.
*								Buf0_TX		output, Corresponding to Buf0_Rx converted output.
*               Buf1_RX   input, corresponding to Buf1 in the IR_Learn_Start fuction.
*               Buf1_TX   output, Corresponding to Buf1_Rx converted output.
*
* Returns    :  
*
**********************************************************************************************************/
extern void Data_transfer(unsigned char Buf0_Rx[], unsigned char Buf0_Tx[],  unsigned char Buf1_Rx[], unsigned char Buf1_Tx[]);

/**********************************************************************************************************
* Description: 	This function is used to test.
*
* Arguments  : 	Buf0		input, corresponding to Buf0_Tx in the Data_transfer fuction.
*								Buf1		input, corresponding to Buf1_Tx in the Data_transfer fuction.
*
* Returns    :  
*
**********************************************************************************************************/
extern void IR_TestSent_Start(unsigned char Buf0[],unsigned char Buf1[]);

#endif

