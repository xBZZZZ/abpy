from sys import stderr,stdout,stdin,exit
READ_BUF_SIZE=128*1024
MAX_DECOMPRESS_SIZE=512*1024

def main():
	from sys import argv
	args=iter(argv)
	try:
		next(args)
		mode=next(args)
	except StopIteration:
		stderr.write("not enough arguments\nrun with '--help' as first argument for help\n")
		exit(1)
	if mode=="--help":
		stdout.write("""usage:
    python3 /path/to/abpy.py <mode> <string and flag arguments>

mode is always first argument

string argument looks like this:
    <name>=<value>

flag argument looks like this:
    <name>

modes:
    --help
        no arguments
        print this help
    abinfo
        string arguments: if
        print arguments for tar2ab mode to make similar ab file
    ab2tar
        string arguments: if, of, pass, pbkdf2engine, aes256engine
        flag arguments: chk
        convert ab to tar
        chk means validate master key checksum (ignored for unencrypted input, makes wrong password less likely to cause late errors or garbage output)
    tar2ab
        string arguments: if, of, ver, pass, rounds, pbkdf2engine, aes256engine
        flag arguments: compr, encr
        convert tar to ab
        ver is required integer and means version (line 2 of ab file)
        rounds is optional positive integer (default 10000) and means number of PBKDF2 iterations
        compr means zlib compress
        encr means encrypt (automatically true if pass=... or rounds=... arguments exist)

... means put something here
if means input file (default stdin)
of means output file (default stdout)
pass means password (default is ask user if needed) (ascii only)
pbkdf2engine means what to use for PBKDF2 (ignored if no encryption):
    hashlib          (default) use hashlib.pbkdf2_hmac (standard library)
    pycryptodome     use Crypto.Protocol.KDF.PBKDF2 (pip install pycryptodome)
    pycryptodomex    use Cryptodome.Protocol.KDF.PBKDF2 (pip install pycryptodomex)
aes256engine means what to use for AES-256 (ignored if no encryption):
    afalg            (default) use linux AF_ALG sockets
    pycryptodome     use Crypto.Cipher.AES.new (pip install pycryptodome)
    pycryptodomex    use Cryptodome.Cipher.AES.new (pip install pycryptodomex)

github: https://github.com/xBZZZZ/abpy
""")
		exit(0)
	def parse_args(str_args,flag_args):
		nonlocal args
		parsed_names=set()
		out={}
		for arg in args:
			try:
				name,val=arg.split("=",1)
			except ValueError:
				if arg not in flag_args:
					stderr.write("bad flag argument %r\n"%arg)
					exit(1)
				if arg in parsed_names:
					stderr.write("duplicate flag argument %r\n"%arg)
					exit(1)
				parsed_names.add(arg)
				out[arg]=None
				continue
			if name not in str_args:
				stderr.write("bad string argument name %r\n"%name)
				exit(1)
			if name in parsed_names:
				stderr.write("duplicate string argument name %r\n"%name)
				exit(1)
			parsed_names.add(name)
			out[name]=val
		args=out
	if mode=="abinfo":
		parse_args(("if",),())
		try:
		    f=open(args["if"],"rb")
		except KeyError:
			f=stdin.buffer
		abinfo_main(f)
	def ifof():
		try:
			yield open(args["if"],"rb")
		except KeyError:
			yield stdin.buffer
		try:
			yield open(args["of"],"wb")
		except KeyError:
			yield stdout.buffer
	def pbkdf2engine_name():
		try:
			name=args["pbkdf2engine"]
		except KeyError:
			return
		if name in {"hashlib","pycryptodome","pycryptodomex"}:
			return name
		stderr.write("unknown pbkdf2engine %r\n"%name)
		exit(1)
	def aes256engine_name():
		try:
			name=args["aes256engine"]
		except KeyError:
			return
		if name in {"afalg","pycryptodome","pycryptodomex"}:
			return name
		stderr.write("unknown aes256engine %r\n"%name)
		exit(1)
	if mode=="ab2tar":
		parse_args({"if","of","pass","pbkdf2engine","aes256engine"},("chk",))
		pbkdf2engine_name2=pbkdf2engine_name()
		aes256engine_name2=aes256engine_name()
		try:
			password=bytes(args["pass"],"ascii")
		except KeyError:
			password=None
		ab2tar_main(*ifof(),password,"chk" in args,pbkdf2engine_name2,aes256engine_name2)
	pbkdf2_engines={"hashlib","pycryptodome","pycryptodomex"}
	if mode=="tar2ab":
		parse_args({"if","of","ver","pass","rounds","pbkdf2engine","aes256engine"},{"compr","encr"})
		try:
			version=int(args["ver"])
		except KeyError:
			stderr.write("ver=... argument is required\n")
			exit(1)
		pbkdf2engine_name2=pbkdf2engine_name()
		aes256engine_name2=aes256engine_name()
		encrypt="encr" in args or "pass" in args or "rounds" in args
		if encrypt:
			try:
				rounds=int(args["rounds"])
				if rounds<1:
					stderr.write("rounds must be > 0\n")
					exit(1)
			except KeyError:
				rounds=10000
			try:
				password=args["pass"]
			except KeyError:
				password=ask_pass()
		else:
			if pbkdf2engine_name2 is not None:
				stderr.write("warning: pbkdf2engine=%s argument unused\n"%pbkdf2engine_name2)
			if aes256engine_name2 is not None:
				stderr.write("warning: aes256engine=%s argument unused\n"%aes256engine_name2)
		tar2ab_main(
			*ifof(),
			version,
			(rounds,password,pbkdf2engine_name2,aes256engine_name2) if encrypt else None,
			"compr" in args
		)
	stderr.write("bad mode %r\nrun with '--help' as first argument for help\n"%mode)
	exit(1)

def abinfo_main(infile):
	version,compressed,encryption_info=read_header(infile)
	stdout.write("ver=%d\n"%version)
	if compressed:
		stdout.write("compr\n")
	if encryption_info is not None:
		stdout.write("encr\nrounds=%d\n"%encryption_info[2])
	stdout.flush()
	exit(0)

def ab2tar_main(infile,outfile,password,chk,pbkdf2engine_name,aes256engine_name):
	outfile.writelines(ab2tar_iterator(infile,password,chk,pbkdf2engine_name,aes256engine_name))
	outfile.flush()
	exit(0)

def ab2tar_iterator(infile,password,chk,pbkdf2engine_name,aes256engine_name):
	version,compressed,encryption_info=read_header(infile)
	if encryption_info is None:
		if password is not None:
			stderr.write("warning: pass=... argument unused\n")
		if chk:
			stderr.write("warning: chk argument unused\n")
		if pbkdf2engine_name is not None:
			stderr.write("warning: pbkdf2engine=%s argument unused\n"%pbkdf2engine_name)
		if aes256engine_name is not None:
			stderr.write("warning: aes256engine=%s argument unused\n"%aes256engine_name)
		initer=read1iter(infile)
	else:
		pbkdf2=pbkdf2engine(pbkdf2engine_name)
		aes256createhandle,aes256closehandle,aes256transform=aes256engine(aes256engine_name)
		password_salt,master_key_checksum_salt,rounds,master_key_blob_iv,master_key_blob=encryption_info
		aes256handle=aes256createhandle(False,pbkdf2(ask_pass() if password is None else password,password_salt,32,rounds),master_key_blob_iv)
		m=b"".join(aes256transform(aes256handle,[master_key_blob],False))
		aes256closehandle(aes256handle)
		if m[0]!=16 or m[17]!=32 or m[50]!=32 or m[83:]!=b"\r\r\r\r\r\r\r\r\r\r\r\r\r":
			stderr.write("invalid decrypted master key blob\nwrong password?\n")
			exit(1)
		master_key=m[18:50]
		master_key_checksum=m[51:83]
		if chk and pbkdf2(master_key,master_key_checksum_salt,32,rounds)!=master_key_checksum and (
			all(x<0x80 for x in master_key) or pbkdf2(
				bytes("".join(chr(x if x<0x80 else x+0xff00) for x in master_key),"utf8"),
				master_key_checksum_salt,32,rounds
			)!=master_key_checksum
		):
			stderr.write("bad master key checksum\n(validation not skipped because chk argument)\nwrong password?\n")
			exit(1)
		initer=decypt_from_file(infile,aes256createhandle(False,master_key,m[1:17]),aes256transform)
	return decompress_from_iterator(initer) if compressed else initer

def tar2ab_main(infile,outfile,version,encrypt_info,compress):
	header,iterator=tar2ab_header_and_iterator(read1iter(infile),version,encrypt_info,compress)
	outfile.write(header)
	del header
	outfile.writelines(iterator)
	outfile.flush()
	exit(0)

def tar2ab_header_and_iterator(initer,version,encrypt_info,compress):
	if compress:
		initer=filter(None,compress_from_iterator(initer))
	if encrypt_info:
		from os import urandom
		from binascii import b2a_hex
		rounds,password,pbkdf2engine_name,aes256engine_name=encrypt_info
		pbkdf2=pbkdf2engine(pbkdf2engine_name)
		aes256createhandle,aes256closehandle,aes256transform=aes256engine(aes256engine_name)
		rb=urandom(192)
		master_key=bytes(b>>1 for b in rb[:32])
		password_salt=rb[32:96]
		master_key_checksum_salt=rb[96:160]
		master_key_blob_iv=rb[160:176]
		data_iv=rb[176:]
		aes256handle=aes256createhandle(True,pbkdf2(password,password_salt,32,rounds),master_key_blob_iv)
		header=b"ANDROID BACKUP\n%d\n%x\nAES-256\n%b\n%b\n%d\n%b\n%b\n"%(
			version,compress,
			b2a_hex(password_salt).upper(),
			b2a_hex(master_key_checksum_salt).upper(),
			rounds,
			b2a_hex(master_key_blob_iv).upper(),
			b2a_hex(b"".join(aes256transform(aes256handle,[
				b"\x10%b %b %b\r\r\r\r\r\r\r\r\r\r\r\r\r"%(
					data_iv,master_key,pbkdf2(master_key,master_key_checksum_salt,32,rounds)
				)
			],False))).upper()
		)
		aes256closehandle(aes256handle)
		initer=encrypt_from_iterator(initer,aes256createhandle(True,master_key,data_iv),aes256transform)
	else:
		header=b"ANDROID BACKUP\n%d\n%x\nnone\n"%(version,compress)
	return header,initer

def ask_pass():
	from getpass import getpass
	return bytes(getpass("enter password -> "),"ascii")

class BadABBody(Exception):
	pass

class BadABHeader(Exception):
	pass

def read_header(infile):
	if infile.read(15)!=b"ANDROID BACKUP\n":
		raise BadABHeader("bad first 15 bytes of file")
	version=str(infile.readline(32),"ascii")
	if version[-1:]!="\n":
		raise BadABHeader("failed to read version in file")
	version=int(version)
	compressed=infile.read(2)
	if compressed==b"0\n":
		compressed=False
	elif compressed==b"1\n":
		compressed=True
	else:
		raise BadABHeader("bad compression flag in file")
	e=infile.read(5)
	if e==b"none\n":
		return version,compressed,None
	if e!=b"AES-2" or infile.read(3)!=b"56\n":
		raise BadABHeader("bad encryption method in file")
	password_salt=infile.read(129)
	if password_salt[128:]!=b"\n":
		raise BadABHeader("failed to read password salt in file")
	from binascii import a2b_hex
	password_salt=a2b_hex(password_salt[:128])
	master_key_checksum_salt=infile.read(129)
	if master_key_checksum_salt[128:]!=b"\n":
		raise BadABHeader("failed to read master key checksum in file")
	master_key_checksum_salt=a2b_hex(master_key_checksum_salt[:128])
	rounds=str(infile.readline(32),"ascii")
	if rounds[-1:]!="\n":
		raise BadABHeader("failed to read rounds in file")
	rounds=int(rounds)
	if rounds<1:
		raise BadABHeader("rounds < 1")
	master_key_blob_iv=infile.read(33)
	if master_key_blob_iv[32:]!=b"\n":
		raise BadABHeader("failed to read master key blob iv in file")
	master_key_blob_iv=a2b_hex(master_key_blob_iv[:32])
	master_key_blob=infile.read(193)
	if master_key_blob[192:]!=b"\n":
		raise BadABHeader("failed to read master key blob in file")
	master_key_blob=a2b_hex(master_key_blob[:192])
	return version,compressed,(password_salt,master_key_checksum_salt,rounds,master_key_blob_iv,master_key_blob)

def pbkdf2engine(name):
	if name is None or name=="hashlib":
		from hashlib import pbkdf2_hmac
		return lambda password,salt,dkLen,count:pbkdf2_hmac("sha1",password,salt,count,dkLen)
	if name=="pycryptodome":
		from Crypto.Protocol.KDF import PBKDF2
	elif name=="pycryptodomex":
		from Cryptodome.Protocol.KDF import PBKDF2
	else:
		assert False
	return PBKDF2

def aes256engine(name):
	if name is None or name=="afalg":
		from struct import pack
		import socket
		if hasattr(socket,"AF_ALG"):
			def make_socket(key):
				with socket.socket(38,5) as s1:
					s1.bind(("skcipher","cbc(aes)"))
					s1.setsockopt(279,1,key)
					return s1.accept()[0]
		else:
			#pypy doesn't support AF_ALG, use libc functions
			from _rawffi.alt import get_libc,types
			libc=get_libc()
			libc_bind=libc.getfunc("bind",(types.sint,types.char_p,types.sint),types.sint)
			libc_accept4=libc.getfunc("accept4",(types.sint,types.void_p,types.void_p,types.sint),types.sint)
			def make_socket(key):
				with socket.socket(38,5) as s1:
					if libc_bind(s1.fileno(),pack("h22s64s",38,b"skcipher",b"cbc(aes)"),88):
						raise OSError("bind failed")
					s1.setsockopt(279,1,key)
					s2fd=libc_accept4(s1.fileno(),0,0,socket.SOCK_CLOEXEC)
					if s2fd<0:
						raise OSError("accept4 failed")
					return socket.socket(38,5,0,s2fd)
		def makehandle(encrypt,key,iv):
			assert len(key)==32
			assert len(iv)==16
			return make_socket(key),[(279,3,pack("i",encrypt)),(279,2,pack("i16s",16,iv))]
		def closehandle(handle):
			handle[0].close()
		def strictrecv(sock,size,unpad):
			rbuf=sock.recv(size)
			if len(rbuf)!=size:
				raise Exception("short recv")
			if unpad:
				padsize=rbuf[-1]
				if padsize not in range(1,17):
					raise BadABBody("invalid decrypted padding last byte")
				if rbuf.count(padsize,-padsize)!=padsize:
					raise BadABBody("decrypted padding bytes not all equal")
				if len(rbuf)==padsize:
					raise StopIteration
				return memoryview(rbuf)[:-padsize]
			return rbuf
		def transform(handle,inbufs,unpad):
			sock,ancdata=handle
			while inbufs:
				slen=slen2=sock.sendmsg(inbufs,ancdata,32832)
				if not slen:
					raise Exception("sendmsg returned 0")
				if 15&slen:
					raise Exception("sendmsg returned number not divisible by 16")
				ancdata.clear()
				for i,inbuf in enumerate(inbufs,1):
					slen2-=len(inbuf)
					if slen2<=0:
						break
				else:
					assert False
				inbufs[:i]=(memoryview(inbuf)[slen2:],) if slen2 else ()
				del inbuf
				try:
					yield strictrecv(sock,slen,unpad and not inbufs)
				except StopIteration:
					return
	else:
		if name=="pycryptodome":
			from Crypto.Cipher.AES import new
		elif name=="pycryptodomex":
			from Cryptodome.Cipher.AES import new
		else:
			assert False
		def makehandle(encrypt,key,iv):
			assert len(key)==32
			assert len(iv)==16
			x=new(key,2,iv=iv)
			return x.encrypt if encrypt else x.decrypt
		def closehandle(handle):
			pass
		bytearrayjoin=bytearray().join
		def non_generator_transform(handle,inbufs,unpad):
			if len(inbufs)==1:
				inbuf=inbufs[0]
				outbuf=bytearray(len(inbuf))
			else:
				inbuf=outbuf=bytearrayjoin(inbufs)
			inbufs.clear()
			handle(inbuf,outbuf)
			if unpad:
				padsize=outbuf[-1]
				if padsize not in range(1,17):
					raise BadABBody("invalid decrypted padding last byte")
				if outbuf.count(padsize,-padsize)!=padsize:
					raise BadABBody("decrypted padding bytes not all equal")
				if len(inbuf)==padsize:
					raise StopIteration
				return memoryview(outbuf)[:-padsize]
			return outbuf
		def transform(handle,inbufs,unpad):
			try:
				yield non_generator_transform(handle,inbufs,unpad)
			except StopIteration:
				pass
	return makehandle,closehandle,transform

def decypt_from_file(infile,handle,transform):
	tail16=infile.read(16)
	if len(tail16)!=16:
		raise BadABBody("encrypted body size less than 16")
	while True:
		chunk=infile.read(READ_BUF_SIZE)
		if not chunk:
			yield from transform(handle,[tail16],True)
			return
		chunksize=len(chunk)
		if 15&chunksize:
			raise BadABBody("encrypted body size not divisible by 16")
		if chunksize!=READ_BUF_SIZE:
			decryptlist=[tail16,chunk]
			del chunk
			yield from transform(handle,decryptlist,True)
			return
		decryptlist=[tail16,memoryview(chunk)[:-16]]
		tail16=chunk[-16:]
		del chunk
		yield from transform(handle,decryptlist,False)

def encrypt_from_iterator(initer,handle,transform):
	tail=b""
	encryptlist=[]
	for chunk in initer:
		tailandchunksize=len(tail)+len(chunk)
		if tailandchunksize<16:
			tail+=chunk
			continue
		if tail:
			encryptlist.append(tail)
		minusremainder=-(15&tailandchunksize)
		if minusremainder:
			encryptlist.append(memoryview(chunk)[:minusremainder])
			tail=chunk[minusremainder:]
		else:
			encryptlist.append(chunk)
			tail=b""
		del chunk
		yield from transform(handle,encryptlist,False)
	padsize=16-len(tail)
	yield from transform(handle,[tail+b"%c"%padsize*padsize],False)

def decompress_from_iterator(initer):
	from zlib import decompressobj
	d=decompressobj(15)
	try:
		while not d.eof:
			yield d.decompress(next(initer),MAX_DECOMPRESS_SIZE)
			while d.unconsumed_tail:
				yield d.decompress(d.unconsumed_tail,MAX_DECOMPRESS_SIZE)
	except StopIteration:
		raise BadABBody("end of file without zlib trailer")
	if d.unused_data or next(initer,False):
		raise BadABBody("data after zlib trailer")

def compress_from_iterator(initer):
	from zlib import compressobj
	c=compressobj(9,8,15,9)
	yield from map(c.compress,initer)
	yield c.flush()

def read1iter(infile):
	class x:
		def x(self):
			pass
	return iter(type(x().x)(infile.read1,READ_BUF_SIZE),b"")

if __name__=="__main__":
	main()