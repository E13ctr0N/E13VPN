@echo off
chcp 65001 >nul
set LOG=X:\1NewProject\VPN\ClientPC\tun-diag.txt

echo === TUN DIAGNOSTIC === > %LOG%
echo %date% %time% >> %LOG%

echo [1/7] Killing old sing-box...
taskkill /F /IM sing-box-x86_64-pc-windows-msvc.exe >nul 2>&1
taskkill /F /IM sing-box.exe >nul 2>&1
timeout /t 5 /nobreak >nul

echo [2/7] Network state BEFORE TUN... >> %LOG%
echo --- interfaces --- >> %LOG%
netsh interface show interface >> %LOG% 2>&1
echo --- dns servers --- >> %LOG%
netsh interface ip show dns >> %LOG% 2>&1
echo --- route print (first 30 lines) --- >> %LOG%
route print | findstr /n "." | findstr /b "^[1-2][0-9]:\|^[1-9]:\|^30:" >> %LOG% 2>&1

echo [3/7] Starting sing-box TUN...
cd /d "C:\Users\User\AppData\Roaming\com.vpnclient.app"
start /b "" "X:\1NewProject\VPN\ClientPC\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe" run -c "C:\Users\User\AppData\Roaming\com.vpnclient.app\singbox.json" > X:\1NewProject\VPN\ClientPC\singbox-log.txt 2>&1
timeout /t 6 /nobreak >nul

echo [4/7] Network state AFTER TUN... >> %LOG%
echo --- interfaces after --- >> %LOG%
netsh interface show interface >> %LOG% 2>&1
echo --- dns after --- >> %LOG%
netsh interface ip show dns >> %LOG% 2>&1

echo [5/7] Flushing DNS and testing...
ipconfig /flushdns >nul 2>&1
timeout /t 2 /nobreak >nul

echo --- nslookup google.com --- >> %LOG%
nslookup google.com >> %LOG% 2>&1

echo --- nslookup via 1.1.1.1 --- >> %LOG%
nslookup google.com 1.1.1.1 >> %LOG% 2>&1

echo --- ping 8.8.8.8 (3 packets) --- >> %LOG%
ping -n 3 8.8.8.8 >> %LOG% 2>&1

echo --- curl httpbin --- >> %LOG%
curl -s --connect-timeout 10 https://httpbin.org/ip >> %LOG% 2>&1
echo. >> %LOG%

echo --- curl 2ip.io --- >> %LOG%
curl -s --connect-timeout 10 https://2ip.io >> %LOG% 2>&1
echo. >> %LOG%

echo [6/7] Waiting for logs...
timeout /t 3 /nobreak >nul

echo [7/7] Stopping sing-box...
taskkill /F /IM sing-box-x86_64-pc-windows-msvc.exe >nul 2>&1

echo --- sing-box log --- >> %LOG%
type X:\1NewProject\VPN\ClientPC\singbox-log.txt >> %LOG% 2>&1

echo.
echo === DONE ===
echo Results: %LOG%
echo Sing-box log: X:\1NewProject\VPN\ClientPC\singbox-log.txt
echo.
type %LOG%
pause
