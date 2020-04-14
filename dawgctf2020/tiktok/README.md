# Writeup for TikTok

*If you've ever wondered 'which Kesha songs are short enough to fit into a Tcache bin?' this is the challenge for you.*

### Challenge Files

+  **`tiktok`**

```
➜ file tiktok
tiktok: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=67770a05ca9e8cc1057161a438e9da38c66321a9, not stripped

➜ checksec tiktok
[*] '/home/.../dawgctf2020/tiktok'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

+ **`libc-2.27.so`**

+ ***`Animal/, Warrior/, Cannibal/, Rainbow/`***

Four folders for each of Kesha's albums, which contain their respective songs as `.txt` files, each beginning with the length of the song in bytes. For example
```
➜ cat Animal/tiktok.txt
2117
Wake up in the morning feeling like P Diddy (Hey, what up girl?)
Grab my glasses, I'm out the door; I'm gonna hit this city (Let's go)
Before I leave, brush my teeth with a bottle of Jack
'Cause when I leave for the night, I ain't coming back
...
```

### Vulnerability 
![import_song](https://www.dropbox.com/s/rlvv9nhr4w5n848/Screenshot%202020-04-13%2021.57.34.png?dl=0)
![play_song](https://www.dropbox.com/s/mc4h9jhp5dkg89u/Screenshot%202020-04-13%2022.12.08.png?dl=0)
![remove_song](https://www.dropbox.com/s/jv6se4koawdfa4d/Screenshot%202020-04-13%2022.05.43.png?dl=0)







