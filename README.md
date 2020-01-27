# ELF File Injector
A simple C script that will let you run arbitrary code on almost every ELF file.

## The method used
This is a fairly simple and old method, but very effective. Basically we search for a gap between the 2 PT_LOAD segments and then inject the payload (written in asm).
After the payload was injected, we need to modify the entry point of the ELF file (in the ELF Header) ,with the address at which the payload resides, and also patch the payload (after it was executed) to jump to the original entry point.

## Installing && Usage
In order to install it, you just need to clone the repository: ```git clone https://github.com/Volkyz/Elij.git```.<br />
After you have cloned it, you need to compile it: ```gcc -o elfij elfij.c```.<br />
The script will ask you for the file that you want to infect and the payload, just provide them and now the file is executing the payload code.

If you don't want to struggle with writing your own payload, you can find some examples of payloads in the **payloads** directory.

## Known issues
The script will work only if the gap is large enough to hold the payload in.<br />
The size of the gap depends on the size of the code, so it may vary from program to program. Thus, some programs may not be able to be injected.

## Upcoming features
- **Developing a way to run payloads more easly**
- **Add PE injection for the windows world**
