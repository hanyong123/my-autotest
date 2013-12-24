Action()
{

	//web_add_cookie("nou_devid=1386751691FED807FD6CA692E747746A; DOMAIN=user.norouter.cn");

	web_reg_find("Text=href=\"/register.php\">",
		LAST);
    
	lr_start_transaction("get_index_page");

	web_url("user.norouter.cn:800", 
		"URL=http://user.norouter.cn:800/", 
		"Resource=0", 
		"RecContentType=text/html", 
		"Referer=", 
		"Snapshot=t1.inf", 
		"Mode=HTML", 
		LAST);
	
	lr_end_transaction("get_index_page", LR_AUTO);

	lr_think_time(5);
	web_reg_find("Text=href=\"/binddev.php\">",
		LAST);
    
	lr_start_transaction("login_post");

	web_submit_form("login.php", 
		"Snapshot=t2.inf", 
		ITEMDATA, 
		"Name=username", "Value={name}", ENDITEM, 
		"Name=password", "Value={passwd}", ENDITEM, 
		LAST);
	
	lr_end_transaction("login_post", LR_AUTO);

	lr_start_transaction("logout");       //ÍË³öµÇÂ¼
	web_link("é€\x80å‡ºâ†’", 
		"Text=é€\x80å‡ºâ†’", 
		"Snapshot=t2.inf", 
		LAST);
	lr_end_transaction("logout", LR_AUTO);
	return 0;
}