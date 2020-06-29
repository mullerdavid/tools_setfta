Compile:
SET DOTNET_PATH=c:\Windows\Microsoft.NET\Framework\v4.0.30319\
%DOTNET_PATH%csc.exe /reference:System.Security.Cryptography.Algorithms.dll /optimize /out:setfta.exe *.cs

----------------------------------------------
How to generate the hash

extension = ".txt"; //the file extension
sid = "S-1-5-21-463486358-3398762107-1964875780-1001"; //the SID of the current user
progid = "txtfile"; //the ProgId of the desired association
regdate = "01d3442a29887400"; //timestamp of the UserChoice registry key
experience = "user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}"; //MS static secret string
hash = Base64(MicrosoftHash(MD5(toLower(extension, sid, progid, regdate, experience))))

----------------------------------------------
Example data

.3g2
S-1-5-21-796063269-1865366272-2249723920-119003
WMP11.AssocFile.3G2
???
user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}
Ejb9dCj7XS4=

.3g2
S-1-5-21-819709642-920330688-1657285119-500
WMP11.AssocFile.3G2
01d4d98267246000
user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}

.3g2S-1-5-21-819709642-920330688-1657285119-500WMP11.AssocFile.3G201d4d98267246000user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}
.3g2s-1-5-21-819709642-920330688-1657285119-500wmp11.assocfile.3g201d4d98267246000user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}
2E 00 33 00 67 00 32 00  73 00 2D 00 31 00 2D 00
35 00 2D 00 32 00 31 00  2D 00 38 00 31 00 39 00
37 00 30 00 39 00 36 00  34 00 32 00 2D 00 39 00
32 00 30 00 33 00 33 00  30 00 36 00 38 00 38 00
2D 00 31 00 36 00 35 00  37 00 32 00 38 00 35 00
31 00 31 00 39 00 2D 00  35 00 30 00 30 00 77 00
6D 00 70 00 31 00 31 00  2E 00 61 00 73 00 73 00
6F 00 63 00 66 00 69 00  6C 00 65 00 2E 00 33 00
67 00 32 00 30 00 31 00  64 00 34 00 64 00 39 00
38 00 32 00 36 00 37 00  32 00 34 00 36 00 30 00
30 00 30 00 75 00 73 00  65 00 72 00 20 00 63 00
68 00 6F 00 69 00 63 00  65 00 20 00 73 00 65 00
74 00 20 00 76 00 69 00  61 00 20 00 77 00 69 00
6E 00 64 00 6F 00 77 00  73 00 20 00 75 00 73 00
65 00 72 00 20 00 65 00  78 00 70 00 65 00 72 00
69 00 65 00 6E 00 63 00  65 00 20 00 7B 00 64 00
31 00 38 00 62 00 36 00  64 00 64 00 35 00 2D 00
36 00 31 00 32 00 34 00  2D 00 34 00 33 00 34 00
31 00 2D 00 39 00 33 00  31 00 38 00 2D 00 38 00
30 00 34 00 30 00 30 00  33 00 62 00 61 00 66 00
61 00 30 00 62 00 7D 00  00 00 
length:0x0000014A
md5:
36 6F 21 E4 D9 8B 5E 3F  8B DD 31 26 62 BD 5C D8

mshash1 buffer: 0028ED40
11 EE EE 8E 72 0E 8F 39

mshash2 buffer: 0028ED60
2D CE 44 9C 1B 21 D4 5F

Signature (0028ED40 XOR 0028ED60)
3C 20 AA 12 69 2F 5B 66

base64
50 43 43 71 45 6d 6b 76 57 32 59 3d
PCCqEmkvW2Y=

----------------------------------------------
Other implementations:

https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/
https://pastebin.com/yL9R0eVE
https://pastebin.com/yVhWeQ3X

