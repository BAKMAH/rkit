# rkit 🕷️
A Linux LD_PRELOAD based userland rootkit that hides files, monitors inward/outward network connections, hides processes, and more.

<div align="center">
    <img src="https://user-images.githubusercontent.com/95945026/153785851-d9b46f21-eb7d-41a1-ab7a-73408d720b1c.png" width="350px"><br>
</div>

## Description
`rkit` hooks several functions in order to hide itself, and avoid being detected. `rkit` comes with an anti rootkit feature that detects if
functions have already been hooked before the rootkit is properly initialized. `rkit` Also checks for byte-patch hooking.

### Features
- File hiding
- Port blocking
- String hiding
- Reverse shell
- Ptrace detection
- Monitoring TCP connections
- Anti rootkit & hooking detection
- Prevent other processes from accessing our memory space

### Hooked functions
- read
- open
- send
- fopen
- write
- fgets
- execve
- readdir
- fopen64
- connect

### Built with
- C

## Getting started
### Compiling
To compile `rkit`, simply execute the following commands:
- `./build.sh`

### Configure
- The configuration file can be located in `src/config.h`.

### Usage
- `export LD_PRELOAD=$PWD/rkit.so`

## Back matter
### Legal disclaimer
Usage of this rootkit for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Credits
```
https://github.com/0x80000000
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
