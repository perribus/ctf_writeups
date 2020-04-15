# Writeup for TikTok

**If you've ever wondered 'Which Ke$ha songs are short enough to fit into a Tcache bin?' this is the challenge for you.**

### Challenge Files

We were given a binary, a libc library and 4 folders (i.e. "albums") with Ke$ha song lyrics inside.  

+  **`tiktok`**

The challenge binary 

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

This is the version of libc the challenge server is using. 

+ ***`Animal/*, Warrior/*, Cannibal/*, Rainbow/*`***

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

The very first step, and probably the most important part of solving this challenge, is to put on Ke$ha. Personally, I preferred her most recent album for vulnerability discovery, and her earlier work for exploitation, but to each their own. 

After we have [Praying](https://www.youtube.com/watch?v=v-Dur3uXXCQ) playing, let's run the binary. This is the output:

```
➜ ./tiktok
Welcome to my tik tok rock bot!
I really like Ke$ha, can you help me make a playlist?

So what would you like to do today?
1. Import a Song to the Playlist
2. Show Playlist
3. Play a song from the Playlist
4. Remove a song from the Playlist
5. Exit
Choice:
```

Next we decompile the binary. Option 2 and 5 are rather straightforward (2 outputs the playlist and 5 exits the program), but Options 1, 3, and 4 look interesting, so we'll look at the functions that get called for those options. 

#### Import Song

Below is the edited decompilation of `import_song`, the function that gets called when selecting Option 1. 

![import_song](../../images/import_song.png)

When `listoptions()` gets called it will `ls -R` the directory it's in. If we netcat into the server running this challenge we can select `1. Import a Song to the Playlist` and the contents of the challenge's directory will get listed. Doing this shows it contains a `flag.txt` and the same song folders and files that we have. 

From lines 20-24 we can see that the user supplies a file path that must exist, can't contain the strings `"flag"` and `".."` and must begin with a capital letter between A and Z (no absolute paths). Given the contents of the challenge directory, the only available option is to send a path of one of the song files, i.e. `<Album_Name>/<song_name>.txt` (*or* just the path of an album directory, i.e. `<Album_Name>/`, which will be relevant later). 

The file path is getting read into an array of structs, which is our playlist of imported songs. Each struct is 56 bytes long, with 7 fields. The decompilation is a little wonky, but `hacky_...` refers to the fields in the first struct in the array. `hacky_fd_reference` is cast as a `DWORD` pointer, whereas everything else is cast as a `QWORD` point so that's why it's being increased `14 * song_ctr` rather than `7*song_ctr`. Below is what the song struct looks like. 

![song_struct](../../images/song_struct.png)

The first 24 bytes of the struct is a 24 bytes array of the song file path. Directly below it is a 4 byte file descripter that gets assigned when the file path is opened. Below that is 4 bytes of padding, and then 3 pointers. The first pointer will point at the file path, the second will point at the file name and the third will point into the heap (given intended program behavior). 

Where do the first two pointers get assigned? In lines 30 and 32, with Ke$ha's favorite libc function, [strtok](http://www.cplusplus.com/reference/cstring/strtok/). While my first instinct was to look there for vulnerabilities, that would be a rookie mistake. Clearly the first thing any good CTF player would do at this situation is put on [TikTok](https://www.youtube.com/watch?v=iP6XpLQM2Cs) by Ke$ha.

Now that the ambiance is set, we can look at the strtoks. The first strtok scans the `song_file_path` to find a token ending in the `/` character. Once done, it replaces that with a null byte, and returns a pointer to the beginning of the token. The second strtok starts at the byte afterwhich the last strtok call left off, so in this case the beginning of our song name, and scans until it finds a `.` character, at which point it replaces that `.` with a nullbyte and returns a pointer to the beginning of the song name. 

This is all just a very verbose way of saying that it parses the parent directory and song name into seperate strings, stripping off the '/' and '.txt'.  
i.e. for `songs[i].song_file_path = "Animal/tiktok.txt"`
```
songs[i].song_file_path = "Animal" + 0x00 + "tiktok" + 0x00 + "txt"

songs[i].song_dirname_ptr = &hacky_dir_reference + 7*i -> 'Animmal' 
songs[i].song_name_ptr = &hacky_name_no_reference + 7*i -> 'tiktok'
```

Now this all becomes very interesting when you realize two things. 

1) The `read` on line 10 reads in up to 24 bytes, exactly the size of `songs[i].song_file_path`. This means that if the user gives a filepath that is 24 bytes long, no null byte will be appended on the end. In each song struct, `songs[i].song_file_path`resides directly above `songs[i].fd` which brings me to 2). 

2) The file descriptor being saved in the struct is already suspicious, and now looks even more so. The first three fds for a Linux process, fd = 0, 1, 2 will (unless otherwise specified) be assigned to stdin, stdout and stderr. So when `open` is called, it will assign a new fd to the file it's opening, beginning with fd = 3. Every time a song is imported a new fd is opened for it, and won't get closed until the user chooses to remove the song. That means that were the user to import, say, 44 songs, `songs[43].fd = 46`, which just so happens to be the ASCII code for `.`.
```
➜  python3
>>> chr(46)
'.'
```
If I import a song path of 24 bytes on my 44th import, and my song path contains no `.` character, then strtok will overwrite the song's file descriptor with a nullbyte, i.e. `songs[43].fd = 0`. A songs file descriptor gets read from when a song is played (we'll see this when we look at the `play_song` function, which means that if I were to play the 44th song, the program would take in input from stdin!

What can we do with this behavior? First we need to put on [Woman](https://www.youtube.com/watch?v=lXyA4MXKIKo) by Ke$ha. Next we look at where the fd gets read from, which is in `play_song` (Option 3). 

#### Play Song

![play_song](../../images/play_song.png)

If a song has not yet been played, i.e. it's `lyrics_ptr_to_heap` has not been set (line 26), `play_song` will read in a line telling it the size of the file (`nbytes`). As you can see in the example song file shown above `Animal/tiktok.txt`is 2117 bytes. If we are inputting from stdin, we could put in a file size of our choosing, including -1. Then, our program mallocs a chunk of exactly `nbytes + 1` (if we were to give -1 as the size `nbytes` then it would `malloc(0)`. It then calls `memset` on the bytes just malloc'd, setting them to null bytes. Then it reads in `nbytes` of data into a heap chunk. If `nbytes = -1` it would read in -1 bytes which, as an unsigned int, is a lot of bytes (the value will wrap around to MAXINT). So with this, we can import 44 songs, and use the last one to overwrite a heap chunk. 

Before we move on to exploitation, let's put on [more Ke$ha](youtube.com/watch?time_continue=4&v=sqV9iWiSWh8) and look at the last function of interest.

#### Remove Song

![remove_song](../../images/remove_song.png)

Option 4 allows a user to remove a song, which sets its struct pointer to null, calls `free` on its lyrics pointer, and closes its file descriptor. It doesn't decrement song count however (although this never matters). 

So, given the `malloc` and `free` it seems like we're working with a heap challenge. 

### Exploitation

First, let's check to see if that vulnerability works how we think it does. 

```python
from pwn import *

p = process(["rr", "record", "./tiktok"])
# p = process("./tiktok") # for running without rr 

def import_song(path):
    p.readuntil("Choice:")
    p.sendline("1")
    print(p.readuntil("Please provide the entire file path."))
    p.sendline(path)
    
def play_song(song):
    p.readuntil("Choice:")
    p.sendline("3")
    p.readuntil("Choice:")
    p.sendline(song)

def remove_song(song):
    p.readuntil("Choice:")
    p.sendline("4")
    p.readuntil("Choice:")
    p.sendline(song)
    
for i in range(1, 44):
    import_song("Animal/godzilla.txt")

album = "Cannibal"
import_song(album + "/" * (24-len(album))) 

play_song("44")
p.sendline("-1")

play_song("44")
p.sendline("-1")
p.send("A" * 100)

p.interactive()
```
To make it easier, I defined a couple helper functions from the start. I'm also running the binary with [https://rr-project.org](https://rr-project.org/) which is great, and I highly recommend it. It records the execution and allows you to step through it as you would in gdb normally (with gef/peda/etc.) but you can also reverse-continue, reverse-step, reverse-next, etc. 

I imported 43 songs normally and for the 44th one, I gave it the file path `Cannibal////////////////` since the name must be 24 bytes without any '.' for this to work. Then I play that song, giving it -1 as a file size and a bunch of 'A's. Let's see what happens in rr/gdb/gef. 

At the end of execution, here is what the song struct array looks like. For the 43 normal song structs, they look like this:

![normal_song_struct](../../images/normal_song_struct.png)

This has been given 19 as its file descriptor at 0x404548. The lyrics pointer at the bottom is null because the song hasn't been played yet. Now let's look at song #44:

![song_struct_44](../../images/song_struct_44.png)

Where there's a 19 in the first struct, there's a 0 in this one where there should be a 46 (at 0x4049e0), and the lyrics pointer to the heap at the bottom of the struct looks promising. Let's see what our heap looks like: 

![heap_overflow](../../images/heap_overflow.png) 

Great, we have a heap overflow! The size of the top chunk has been overwritten with `A`. Now we have to make this useful somehow. 

Given that this is libc-2.27.so, that means that the heap will have tcache bins. Tcache is a set of 64 singly linked lists, one for increasing chunk sizes up to 1032 (at least for libc-27). When a chunk within this size range gets free, it will end up in its corresponding tcache bin if there's room (each bin holds up to 7 chunks). Conversly, when a chunk in this size range is requested by the program, the heap manager checks it's corresponding tcache bin _first_ to see if there's a freed chunk it can use. Tcache was added to improve performance, and as such they removed many of the security checks, which will be useful to us in this challenge. 

[This](https://syedfarazabrar.com/2019-10-12-pico
-2019-heap-challs/) is a great writeup of a tcache attack, which goes into detail on the glibc heap implementation . It also contains some helpful diagrams of heap chunks which I've adapted for this post.

Below is an allocated chunk on the heap. AMP are bits with information on the heap, P is the only one we care about: it will get set if the previous chunk is in use (i.e. not freed). The top two sections are part of the chunk's header. After this is the actual stored in the chunk and this is where the pointer malloc returns will point.

```
chunk A     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (if P = 0) |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
addr of A   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             chunk A data starts here...                       .   
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
chunk B     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|M|1|
addr of B   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
[Source](https://syedfarazabrar.com/2019-10-12-picoctf-2019-heap-challs/)

When a chunk gets freed and pushed onto the top of a tcache bin (which is a singly linked list), it becomes the new head chunk and stores a pointer the old head chunk of the tcache bin. If a tcache bin has two elements, chunk A and chunk X in it with X as the head element, it may look like this:

```
 chunk X    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           
            | Size of previous chunk (if P = 0)   |           
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           
            | Size of chunk X               |A|M|P|          
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          
tc bin ->   | Pointer to next chunk in tcache bin | ----+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |          
            .                                     .     |   
            . Unused space                        .     |    
            .                                     |     |       
chunk Y     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |      
            | Size of chunk X                     |     |     
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |      
            | Size of chunk Y               |A|M|0|     |      
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |     
                              .                         |
                              .                         |
                              .                         |
  chunk A   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |      
            | Size of previous chunk (if P = 0)   |     |      
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |    
            | Size of chunk X               |A|M|P|     |      
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     |      
tc bin ->   | Null (no next element)              |  <--+  
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          
            .                                     .           
            . Unused space                        .          
            .                                     |         
chunk B     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+            
            | Size of chunk X                     |           
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           
            | Size of chunk Y               |A|M|0|            
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           
```
Tcache bins are, for lack of a better term, **dumb**. If you overwrite the pointer of a chunk, let's say chunk X, in the tcache with your own address, when chunk X is the head of tcache bin and then gets reallocated, the tcache bin will think its _new_ head is whatever is at the address you wrote, _even if it's not on the heap_. We can use our overwrite to allocate a chunk anywhere in writeable address space.  

Let's say we first free chunk X so it ends up at the top the tcache bin for its size (in this case let's say 0x20). If playing song #44 allocates a chunk W right above chunk X, then we can overwrite the tcache next pointer of chunk X. When we play song #44 we call malloc(0), which (perhaps unintuitively) means chunk W will have a size of 0x20 (the smallest possible heap chunk). We pass in overwrite the header of chunk X to have the same values it had before, and then overwrite the address with our new address. If we wanted to overwrite another song's file descripter with 0, we can point it at the address of `songs[i].fd`. 

```
 chunk W    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
            | Size of previous chunk (if P = 0)     |          
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     
            | 0x21 (Size of 0x20 + |0|0|1|)         |           
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+++  
            | This is where our data will start     |          
            | <0x0000000000000000>                  |      
            | <0x0000000000000000>                  |                  
chunk X     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ chunk A
            | <0x0000000000000000>                  |            | Size of previous chunk (if P = 0)   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | <0x0000000000000021> (size of chunk X)|            | Size of chunk A               |A|M|
tc bin      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
for 0x20 -> | <0x0000000000404078>                  |  ___       | Null (no next element)              |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                                       .    |       .                                     .
            . Unused space                          .    |       . Unused space                        .
            .                                       |    |       .                                     |
chunk Y     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ chunk B
            | Size of chunk X                       |    |       | Size of chunk A                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Size of chunk Y                 |A|M|0|    |       | Size of chunk B               |A|M|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |       -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                         |
                                                         V     
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    
                  addr = 0x404078   |                songs[0].fd            |          
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
                        
```
Now when chunk X gets allocated and taken off

If you're interested in knowing more about heap attacks Azeria's [post](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/) on the glibc heap is a good place to start, as well as Shellphish's [how2heap](https://github.com/shellphish/how2heap) repository which also links to further resources. 




