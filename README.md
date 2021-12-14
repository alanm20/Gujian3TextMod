9# Gujian3TextMod
A Stub DLL replace in-game text messages.

Original DirectSound wrapper DLL implementation from (https://github.com/elishacloud/DirectX-Wrappers)
The code was modified to work only as text mod for Gujian3.exe.

## Building the app
Compiled with Visual Studio 2019

Solution file: src/Gujian3TexMod.sln
Target:  x64 Release

## Installation
Copy dsound.dll  to Steam game directory bin64/ folder next to Gujian3.exe
Copy text.bin if you have game version 1.2 or text1302142.bin for version 1.3 to  bin64 folder.

Use https://github.com/Kaplas80/GuJian3Manager to export text.bin (text1302142.bin for v1.3) to json format and import localized json file back to text.bin

## Uninstall
remove dsound.dll text.bin text1302142.bin from bin64 folder


## Special Thanks
- [Kaplas](https://zenhax.com/memberlist.php?mode=viewprofile&u=5785) (find where the decrypted size is stored, [Gujian3Manager](https://github.com/Kaplas80/GuJian3Manager))
- eprilx [Gujian3TextEditor](https://github.com/eprilx/Gujian3TextEditor), .

## License:  
MIT
