' start.vbs
' Description: This script runs a Python script in the background without showing a console window.
' 直接在计划任务中运行 Python 脚本似乎会有选择打开方式的窗口弹出，暂时用 VBS 来解决这个问题吧。
Dim Wsh
Set Wsh = WScript.CreateObject("WScript.Shell")
Wsh.Run ".\login.pyw",false,false
Set Wsh=NoThing
WScript.quit
