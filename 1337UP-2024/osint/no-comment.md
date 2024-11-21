# OSINT: No Comment

1. Use [ExifTool](https://en.wikipedia.org/wiki/ExifTool) to extract image metadata

<img src="https://github.com/user-attachments/assets/097e47ab-d8ae-4cc2-a6b8-8b2684077fb5" width="500" alt="ripple">

```bash
$ exiftool ripple.jpg
ExifTool Version Number         : 12.62
File Name                       : ripple.jpg
Directory                       : .
File Size                       : 6.5 MB
File Modification Date/Time     : 2024:11:17 16:27:48-06:00
File Access Date/Time           : 2024:11:17 16:27:56-06:00
File Inode Change Date/Time     : 2024:11:17 16:31:12-06:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Comment                         : /a/pq6TgwS
Image Width                     : 4032
Image Height                    : 3024
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 4032x3024
Megapixels                      : 12.2
```

2. I've used Imgur a lot for creating photo albums, so I pretty quickly realized that the `/a/pq6TgwS` comment was the end of an Imgur url: https://imgur.com/a/pq6TgwS (the `/a/` part was the giveaway)
<img src="https://github.com/user-attachments/assets/3a4100c8-2bdb-4df8-ba27-61cc40b36bcb" width="500" alt="ripple">

3. The Imgur image has a base64 string as its caption (you can tell it's base64 b/c of the `=` padding), which I decoded to find a pastebin link:

```
$ echo "V2hhdCBhICJsb25nX3N0cmFuZ2VfdHJpcCIgaXQncyBiZWVuIQoKaHR0cHM6Ly9wYXN0ZWJpbi5jb20vRmRjTFRxWWc=" | base64 -d
What a "long_strange_trip" it's been!

https://pastebin.com/FdcLTqYg
```

4. Clicking on the pastebin link, I was greeted with a locked paste. However, the password was pretty obviously the `long_strange_trip` string from the decoded base64. Inside the paste, is a hex code: `25213a2e18213d2628150e0b2c00130e020d024004301e5b00040b0b4a1c430a302304052304094309` (you can tell b/c it's comprised of only 0-9 + a-e)

I tried decoding and got this junk:
```
$ echo "25213a2e18213d2628150e0b2c00130e020d024004301e5b00040b0b4a1c430a302304052304094309" | xxd -r -p
%!:.!=&(
@0[     ,

   JC
0##	C	
```
I was pretty confused after this, so I went back to the pastebin to see if I missed anything and, lo and behold, I did:

![Screenshot from 2024-11-17 20-24-50](https://github.com/user-attachments/assets/ee5ce864-11e2-4717-ab8a-6a32c82eb40b)

Doing exactly what this is telling me to I tried XORing the hex with the password and got the flag!
```python
encrypted = bytes.fromhex("25213a2e18213d2628150e0b2c00130e020d024004301e5b00040b0b4a1c430a302304052304094309")
key = b"long_strange_trip"

decrypted = b''
for i in range(len(encrypted)):
    decrypted += bytes([encrypted[i] ^ key[i % len(key)]])

print(decrypted.decode()) # INTIGRITI{...}
```
