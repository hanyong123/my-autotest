Action()
{
	lr_output_message("name=%s",lr_eval_string("{name}"));
	web_reg_find("Text=href=\"/register.php\">",
		LAST);
    
	lr_start_transaction("rep");

	web_url("user.norouter.cn:800",
		"URL=http://user.norouter.cn:800/",
		"Resource=0",
		"RecContentType=text/html",
		"Referer=",
		"Snapshot=t1.inf",
		"Mode=HTML",
		LAST);
	
	lr_end_transaction("rep", LR_AUTO);

	lr_think_time(4);

	web_reg_find("Text=href=\"/login.php\">",
		LAST);
    
	lr_start_transaction("rep");

	web_link("新用户注�\x8C",
		"Text=新用户注�\x8C",
		"Snapshot=t2.inf",
		LAST);
	
	lr_end_transaction("rep", LR_AUTO);

	lr_think_time(20);

	web_reg_find("Text=href=\"/binddev.php\">",
		LAST);
    
	lr_start_transaction("rep");

	web_submit_form("register.php",
		"Snapshot=t3.inf",
		ITEMDATA,
		"Name=username", "Value={name}", ENDITEM,
		"Name=nickname", "Value={nicky}", ENDITEM,
		"Name=password", "Value={passwd}", ENDITEM,
		"Name=passwordtwo", "Value={passwd}", ENDITEM,
		LAST);
	
	lr_end_transaction("rep", LR_AUTO);

return 0;
}
