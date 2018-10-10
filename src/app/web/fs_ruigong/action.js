function Restart()
{        
	if(confirm('Are you sure to restart system?'))
	{
	   document.systeminfo.submit();
	} 
}

function UpGrade()
{        
	if (document.FirmWareUpgrade.file.value == "")
	{
		alert("Please select file first");
		return ;
	}
	if(confirm('Are you sure to update firmware?')){
	   document.FirmWareUpgrade.submit() ;
	} 	
}

function saveconfig()
{
	if(confirm('Are you sure to save?\n'))
	{
		return true;	  
	}	  
	else
	{
		return false;
	}	
}

function key()
{
	var objEncry = document.getElementById("Encry").value;	
  
	if(objEncry == 0)	// open
	{
		document.all.KeyType.disabled=true;
		document.all.Key.disabled=true;
	}
	else	//web64 web128
	{
		document.all.KeyType.disabled = false;
		document.all.Key.disabled = false;
	}
}

function strlen(str) 
{
	var len = 0;
	for (var i = 0; i < str.length; i++)
	{
		if (str.charCodeAt(i) > 255) len += 2; else len ++;
    }
	return len;
}

function isIp(str)
{ 
	var sa=str.split(".");
	if(sa.length!=4) return false;
	for(var i=0;i<sa.length;i++)
	{ 
		if(!(/^(\d)+$/g).test(sa[i]) || (sa[i]<0) || (sa[i]>255)) return false; 
	}
	return true;
} 

function Form1_MM_popupMsg()
{
	  var Encry_var = document.getElementById("Encry").value;
	  var Key_var = document.getElementById("Key").value;
	  var KeyType_var = document.getElementById("KeyType").value;
	  var Mode_var = document.getElementById("Mode").value;	  
	  if(Mode_var != 0)
	  {
		  if(Encry_var == 1)
		  {
				if(KeyType_var == 0)
			  {
					if(strlen(Key_var) != 10)
					{
						alert('In WEP64 Mode Key(HEX) Length should be  10 characters!');
						return false;	
					}	  
			  }
			  else if(KeyType_var == 1)
			  {
						if(strlen(Key_var) != 5)
						{
							alert('In WEP64 Mode Key(ASCII) Length should be  5 characters!');
							return false;	
						}	  
				}
			}
		  else if(Encry_var == 2)
		  {
				if(KeyType_var == 0)
			  {
					if(strlen(Key_var) != 26)
					{
						alert('In WEP128 Mode Key(HEX) Length should be  26 characters!');
						return false;
					}		  
			  }
			  else if(KeyType_var == 1)
			  {
			  	if(strlen(Key_var) != 13)
					{
						alert('In WEP128 Mode Key(ASCII) Length should be  13 characters!');
						return false;		 
					} 
			  }	  	
		  }
	  }
    return saveconfig();
}

function Form3MM_popupMsg(){
	  var Port_var=document.getElementById("Port").value;
	  var Auto_obj=document.all.Auto.checked;
	  if(Auto_obj==1)
	  {
		  if(parseInt(Port_var)>65536||parseInt(Port_var)<1)
		  {
	              alert('Port Number Error!');
	                 return false;	   
		  }	   
	  }
	return saveconfig();
}

function MM_popupMsg() { //v1.0
      var IP_var=document.getElementById("Ip").value;
      var Sub_var=document.getElementById("Sub").value;
      var Gate_var=document.getElementById("Gate").value;
      var Dns_var=document.getElementById("Dns").value;
	  if(!isIp(IP_var))
	  {
              alert('Fixed IP Address Error!');
                 return false;
	  }
	  if(!isIp(Sub_var))
	  {
              alert('Subnet mask Address Error!');
                 return false;
	  }	  if(!isIp(Gate_var))

	  {
              alert('Gateway Address Error!');
                 return false;
	  }	  if(!isIp(Dns_var))

	  {
              alert('DNS Address Error!');
                 return false;
	  }	   
     return saveconfig();
}

function dhcp1()
{
	var obj=document.all.Dhcp.checked;
	if(obj)
	{
		document.all.Ip.disabled=true;
		document.all.Sub.disabled=true;
		document.all.Gate.disabled=true;
		document.all.Dns.disabled=true;
	}
	else
	{
		document.all.Ip.disabled=false;
		document.all.Sub.disabled=false;
		document.all.Gate.disabled=false;
		document.all.Dns.disabled=false;
	}
}

function mode()
{
	var obj=document.all.Mode.value;
	
	if(obj==0)	// sta
	{
		document.all.Encry.disabled=true;
		document.all.KeyType.disabled=true;
		document.all.Key.disabled=false;
	}
	else	// ap adhoc
	{
		document.all.Encry.disabled=false;
		key();
	}
	if(obj==2)
	{
		document.all.Dhcp.checked=true;
		document.all.Dhcp.disabled=true;
		document.all.Gate.disabled=true;
		document.all.Dns.disabled=true;
		document.all.Ip.disabled=false;
		document.all.Sub.disabled=false;
	}
	else
	{
		document.all.Dhcp.disabled=false;
		document.all.Gate.disabled=false;
		document.all.Dns.disabled=false;
		dhcp1();
	}	
}