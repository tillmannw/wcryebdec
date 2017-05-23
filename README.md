# wcryebdec
A quick-and-dirty WannaCry ETERNALBLUE payload decoder. Extracts WannaCry payloads from a SMB Trans2 stream. Runs on Trans2 streams from reassembled TCP sessions.

```
$ python wcryebdec.py wannacry-smb-session.bin 
decoded SMB stream dumped to wannacry-smb-session.bin.trans2stream.6151
decrypted SMB stream dumped to wannacry-smb-session.bin.trans2stream.6151.dec
extracted payload dumped to wannacry-smb-session.bin.trans2stream.6151.dec.payload

$ file wannacry-smb-session.bin.trans2stream.6151.dec.payload
wannacry-smb-session.bin.trans2stream.6151.dec.payload: PE32 executable (GUI) Intel 80386, for MS Windows

```
