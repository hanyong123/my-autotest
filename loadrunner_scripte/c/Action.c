#include "lrs.h"
#include "n_md5.h"

Action()
{
	char ran[16];
	char* p;
	char id_rand[50]="\x1B\xE8\xE7\x8D\x76\x5A\x2E\x63\x33\x9F";
	char devid[50]="\\x00\\x00\\x2E\\x0D\\x00\\x01\\xA6\\x11";
	char* data;
	int size;
	char digest[16];
	char buf[1024];
	oemMD5_CTX context;

	//id 有18个字节前8个字节是dev_id 后10个字节是id_rand用于生成MD5
	lr_save_string(devid,"dev_id");
	lrs_set_receive_option(Mismatch,MISMATCH_CONTENT);
	lrs_send("socket0", "buf0", LrsLastArg);        //check  id
	lrs_receive("socket0", "buf1", LrsLastArg);
	lrs_set_receive_option(Mismatch,MISMATCH_SIZE);
	lrs_send("socket0", "buf3", LrsLastArg);
	lrs_receive("socket0","buf4",LrsLastArg);
	p = lrs_get_received_buffer("socket0",18,16,NULL);
	memcpy(ran,p,16);
	oemMD5Init(&context);
    oemMD5Update(&context,(unsigned char*)id_rand,10);
    oemMD5Update(&context,(unsigned char*)ran,16);
    oemMD5Final((unsigned char*)digest,&context);
	lrs_get_buffer_by_name("buf5",&data,&size);
	memcpy(data+30,digest,16);
	buffer_convert_to_hex_string(data,131,buf);
	lrs_set_receive_option(Mismatch,MISMATCH_CONTENT);
	lrs_set_send_buffer("socket0",buf,strlen(buf));
	lrs_send("socket0", "buf5", LrsLastArg);
	lrs_receive("socket0","buf6",LrsLastArg);
	
	lrs_send("socket0", "buf3", LrsLastArg);
	lrs_receive("socket0", "buf7", LrsLastArg);
	lrs_set_receive_option(Mismatch,MISMATCH_SIZE);
    return 0;
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


