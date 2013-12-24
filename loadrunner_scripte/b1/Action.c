#include "lrs.h"


Action()
{
	lr_save_string(randmac,"mac");
	lr_save_string(randip,"ip");

	lrs_get_buffer_by_name("buf4",&data,&size);
	memcpy(data+18,dev_id,8);
	buffer_convert_to_hex_string(data,44,buf);
	lrs_set_receive_option(Mismatch,MISMATCH_CONTENT);
	lrs_set_send_buffer("socket0",buf,strlen(buf));
	lrs_send("socket0", "buf4", LrsLastArg);
	lrs_receive("socket0","buf8",LrsLastArg);
	lrs_set_receive_option(Mismatch,MISMATCH_SIZE);
    lr_think_time(1);
    return 0;
}

