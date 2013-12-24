#include "lrs.h"
#include "n_md5.h"

char* data;
char* ids;
int size;
char buf[1024];
char dev_id[9];
char id_rand[10];
char ran[16];
char digest[16];
char* p;
int i = 0;
char randmac[25];
char randip[17];
oemMD5_CTX context;
int id, scid;
char *vuser_group;



vuser_init()
{
    lrs_startup(257);	
    lrs_create_socket("socket0","UDP","RemoteHost=ad3.norouter.cn:1500",LrsLastArg);

	lr_whoami(&id, &vuser_group, &scid);
	srand(id+time(NULL)); 
	rand_mac(randmac);
	rand_ip(randip);
	lr_output_message("randip=%s",randip);
	lr_output_message("rand_mac=%s",randmac);
	lr_save_string(randmac,"mac");
	lr_save_string(randip,"ip");
    return 0;
}

