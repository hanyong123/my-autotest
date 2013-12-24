#include "lrs.h"


Action()
{
	lr_save_string(randmac,"mac");
	lr_save_string(randip,"ip");
    lrs_send("socket0", "buf0", LrsLastArg);
    lrs_receive("socket0", "buf1", LrsLastArg);
    ids = lrs_get_received_buffer("socket0",18,18,NULL);
	buffer_convert_to_hex_string(ids,18,buf);
	lr_output_message("ids=%s",buf);
    lrs_get_buffer_by_name("buf2",&data,&size);
	memcpy(dev_id,ids,8);
	memcpy(id_rand,ids+8,10);
	memcpy(data+18,dev_id,8);
	buffer_convert_to_hex_string(data,36,buf);
	//lr_output_message("buf=%s",buf);
    lrs_set_receive_option(Mismatch,MISMATCH_CONTENT);
    lrs_set_send_buffer("socket0",buf,strlen(buf));
	lrs_send("socket0", "buf2", LrsLastArg);
    lrs_receive("socket0","buf3",LrsLastArg);
	lrs_set_receive_option(Mismatch,MISMATCH_SIZE);
	lrs_get_buffer_by_name("buf4",&data,&size);
	memcpy(data+18,dev_id,8);
	buffer_convert_to_hex_string(data,44,buf);
	lrs_set_send_buffer("socket0",buf,strlen(buf));
	lrs_send("socket0", "buf4", LrsLastArg);
	lrs_receive("socket0","buf5",LrsLastArg);
	p = lrs_get_received_buffer("socket0",18,16,NULL);
	memcpy(ran,p,16);
    oemMD5Init(&context);
    oemMD5Update(&context,(unsigned char*)id_rand,10);
    oemMD5Update(&context,(unsigned char*)ran,16);
    oemMD5Final((unsigned char*)digest,&context);
	memset(digest,0,16);  //设置错误的MD5验证
	lrs_get_buffer_by_name("buf6",&data,&size);
	memcpy(data+18,dev_id,8);
	memcpy(data+30,digest,16);
	buffer_convert_to_hex_string(data,131,buf);
	lrs_set_receive_option(Mismatch,MISMATCH_CONTENT);
	lrs_set_send_buffer("socket0",buf,strlen(buf));
	lrs_send("socket0", "buf6", LrsLastArg);
	lrs_receive("socket0","buf7",LrsLastArg);
	lrs_set_receive_option(Mismatch,MISMATCH_SIZE);
    return 0;
}

hex_dump(char* buf,int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		lr_output_message("\\x%02X",(unsigned char)buf[i]);
	}
}
buffer_convert_to_hex_string(char* in_buff,int len,char* out_buf)
{
	int i;
	char* p;
	p = out_buf;
	memset(out_buf,0,sizeof(out_buf));
	for(i=0;i<len;i++)
	{
		sprintf(p,"\\x%02X",(unsigned char)in_buff[i]);
		p = p + 4;

	}
}

rand_mac(char* outbuf)
{
    char hexdigit[16] = "0123456789ABCDEF";
	char m1;
	char m2;
	char m3;
	char m4;
	char m5;
	char m6;
	char m7;
	char m8;
	char m9;
	char m10;
	char m11;
	char m12;
	
	m1 = hexdigit[rand() % sizeof(hexdigit)];
	m2 = hexdigit[rand() % sizeof(hexdigit)];
	m3 = hexdigit[rand() % sizeof(hexdigit)];
	m4 = hexdigit[rand() % sizeof(hexdigit)];
	m5 = hexdigit[rand() % sizeof(hexdigit)];
	m6 = hexdigit[rand() % sizeof(hexdigit)];
	m7 = hexdigit[rand() % sizeof(hexdigit)];
	m8 = hexdigit[rand() % sizeof(hexdigit)];
	m9 = hexdigit[rand() % sizeof(hexdigit)];
	m10 = hexdigit[rand() % sizeof(hexdigit)];
	m11 = hexdigit[rand() % sizeof(hexdigit)];
	m12 = hexdigit[rand() % sizeof(hexdigit)];
	sprintf(outbuf,"\\x%c%c\\x%c%c\\x%c%c\\x%c%c\\x%c%c\\x%c%c",m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12);
	
}

rand_ip(char* outbuf)
{
	char hexdigit[16] = "0123456789ABCDEF";
	char m1;
	char m2;
	char m3;
	char m4;
	char m5;
	char m6;
	char m7;
	char m8;
	
	m1 = hexdigit[rand() % sizeof(hexdigit)];
	m2 = hexdigit[rand() % sizeof(hexdigit)];
	m3 = hexdigit[rand() % sizeof(hexdigit)];
	m4 = hexdigit[rand() % sizeof(hexdigit)];
	m5 = hexdigit[rand() % sizeof(hexdigit)];
	m6 = hexdigit[rand() % sizeof(hexdigit)];
	m7 = hexdigit[rand() % sizeof(hexdigit)];
	m8 = hexdigit[rand() % sizeof(hexdigit)];
	sprintf(outbuf,"\\x%c%c\\x%c%c\\x%c%c\\x%c%c",m1,m2,m3,m4,m5,m6,m7,m8);
}




