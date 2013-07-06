Dim $browser
Dim $flag



$browser = $CmdLine[1]

Local $file = FileOpen("autoit_status", 2)
FileWrite($file,"False")
FileClose($file)

If $browser = "firefox" Then
   WinWait("需要验证","",60)
   WinWaitActive("需要验证","",60)
EndIf


Send('435')
Sleep(2000)
Send("{Tab}")
Sleep(2000)
Send('456')
Sleep(2000)
Send("{ENTER}")
Sleep(2000)

$flag = WinWaitActive("需要验证","",2)
If $flag = 0 Then
   Exit
EndIf

Send('678')
Sleep(2000)
Send("{Tab}")
Sleep(2000)
Send('768')
Sleep(2000)
Send("{ENTER}")
Sleep(2000)

$flag = WinWaitActive("需要验证","",2)
If $flag = 0 Then
   Exit
EndIf

Send('678')
Sleep(2000)
Send("{Tab}")
Sleep(2000)
Send('675')
Sleep(2000)
Send("{ENTER}")
Sleep(2000)

$flag = WinWaitActive("需要验证","",2)
If $flag = 0 Then
   Local $file = FileOpen("autoit_status", 2)
   FileWrite($file,"True")
   FileClose($file)
Else
   Send("{ESC}")
EndIf



