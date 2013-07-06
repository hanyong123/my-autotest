Dim $user
Dim $passwd
Dim $browser
Dim $flag

$user = $CmdLine[1]
$passwd = $CmdLine[2]
$browser = $CmdLine[3]
$status = $CmdLine[4]


Local $file = FileOpen("autoit_status", 2)
FileWrite($file,"False")
FileClose($file)

If $browser = "firefox" Then
   WinWait("需要验证","",60)
   WinWaitActive("需要验证","",60)
EndIf


Send($user)
Sleep(2000)
Send("{Tab}")
Sleep(2000)
Send($passwd)
Sleep(2000)
Send("{ENTER}")
Sleep(2000)

If $status = "fail" Then
   $flag = WinWaitActive("需要验证","",2)
   if $flag <> 0 Then
	  Local $file = FileOpen("autoit_status", 2)
	  FileWrite($file,"True")
	  FileClose($file)
	  Sleep(2000)
	  Send("{Esc}")
   EndIf
EndIf


If $status = "suc" Then
   $flag = WinWaitActive("需要验证","",2)
   If $flag = 0 Then
	  Local $file = FileOpen("autoit_status", 2)
	  FileWrite($file,"True")
	  FileClose($file)
   Else
	  Sleep(2000)
	  Send("{Esc}")
   EndIf
EndIf

