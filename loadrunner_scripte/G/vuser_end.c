#include "lrs.h"


vuser_end()
{
	lrs_close_socket("socket0");
    lrs_cleanup();
    return 0;
}

