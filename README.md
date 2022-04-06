# rkit 🕷️
A Linux LD_PRELOAD based userland rootkit that hides files, monitors outgoing network connections, hides strings, hides processes, and more.

<div align="center">
    <img src="https://cdn-icons-png.flaticon.com/512/616/616483.png" width="250px"><br>
</div>

## Description
`rkit` hooks several functions in order to hide itself, and avoid being detected. `rkit` comes with an anti rootkit feature that detects if
functions have already been hooked before the rootkit is properly initialized. `rkit` also checks for byte-patch hooking.

### Features
- Anti VM
- File hiding
- Port blocking
- String hiding
- Reverse shell
- Ptrace detection
- Monitoring TCP connections
- Anti rootkit & hooking detection

### Hooked functions
- read
- open
- send
- write
- fgets
- fopen
- openat
- readdir
- connect
- fopen64

### Built with
- C

## Getting started
### Compiling
To compile `rkit`, simply execute the following command:
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
