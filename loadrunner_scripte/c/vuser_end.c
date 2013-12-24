#include "lrs.h"


vuser_end()
{
    lrs_cleanup();
	lrs_close_socket("socket0");
    return 0;
}

