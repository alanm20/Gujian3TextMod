## Gujian3TextMod
A Stub DLL replace in-game text messages.

- Original DirectSound wrapper DLL implementation from [DirectX-Wrappers](https://github.com/elishacloud/DirectX-Wrappers)

- The code was modified to work only as text mod for Gujian3.exe.

## Building the app
- Compiled with Visual Studio 2019

- Solution file: src/Gujian3TexMod.sln
- Target:  x64 Release

## Installation
- Copy dsound.dll  to Steam game directory bin64/ folder next to Gujian3.exe
- Copy text.bin if you have game version 1.2 or text1302142.bin for version 1.3 to  bin64 folder.

- Use https://github.com/Kaplas80/GuJian3Manager to export text.bin (text1302142.bin for v1.3) to JSON format and import localized JSON file back to text.bin

## Uninstall
- remove dsound.dll text.bin text1302142.bin from bin64 folder


## Special Thanks
- [Kaplas](https://zenhax.com/memberlist.php?mode=viewprofile&u=5785) (find where the decrypted size is stored, [Gujian3Manager](https://github.com/Kaplas80/GuJian3Manager))
- eprilx [Gujian3TextEditor](https://github.com/eprilx/Gujian3TextEditor), .

## License:  
### License

Copyright (C) 2021 alanm

This software is  provided 'as-is', without any express  or implied  warranty. In no event will the
authors be held liable for any damages arising from the use of this software.
Permission  is granted  to anyone  to use  this software  for  any  purpose,  including  commercial
applications, and to alter it and redistribute it freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not claim that you  wrote the
      original  software. If you use this  software  in a product, an  acknowledgment in the product
      documentation would be appreciated but is not required.
   2. Altered source versions must  be plainly  marked as such, and  must not be  misrepresented  as
      being the original software.
   3. This notice may not be removed or altered from any source distribution.

Code in this project is taken from:
Elisha Riedlinger [DirectX-Wrappers](https://github.com/elishacloud/DirectX-Wrappers)
