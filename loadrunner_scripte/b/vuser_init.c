#include "lrs.h"


vuser_init()
{
    lrs_startup(257);	

    lrs_create_socket("socket0","UDP","RemoteHost=ad3.norouter.cn:1500",LrsLastArg);
    
    return 0;
}

