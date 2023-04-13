from sys import stderr,stdout,stdin,argv

READ_BUF_SIZE=2*1024*1024
MAX_DECOMPRESS_SIZE=4*1024*1024

def main():
	args=argv[1:]
	if "--help" in args:
		stdout.write("""usages:
\t--help
\tmode=abinfo [if=...] [of=...]
\tmode=ab2tar [if=...] [of=...] [pass=...]
\tmode=tar2ab [if=...] [of=...] [pass=...] [rounds=...] ver=... [flags=[e][c]]

[STRING] means STRING is optional
... means put something here

mode means what to do
if means input file (default stdin)
of means output file (default stdout)
pass means password (implies e flag, ascii only, default ask if needed)
rounds means number PBKDF2 iterations (implies e flag, positive integer, default 10000)
ver means version (integer)

flags:
\te means encrypt
\tc means compress

github: https://github.com/xBZZZZ/abpy
""")
		exit(0)
	args=dict(a.split("=",1) for a in args)
	try:
		mode=args["mode"]
	except KeyError:
		stderr.write("mode=... argument is required\nrun with --help for help\n")
		exit(1)
	infile_path=args.get("if",None)
	outfile_path=args.get("of",None)
	if mode=="abinfo":
		abinfo_main(
			stdin.buffer if infile_path is None else open(infile_path,"rb"),
			stdout.buffer if outfile_path is None else open(outfile_path,"wb"),
		)
	if mode=="ab2tar":
		password=args.get("pass",None)
		ab2tar_main(
			stdin.buffer if infile_path is None else open(infile_path,"rb"),
			stdout.buffer if outfile_path is None else open(outfile_path,"wb"),
			None if password is None else bytes(password,"ascii")
		)
	if mode=="tar2ab":
		try:
			version=int(args["ver"])
		except KeyError:
			stderr.write("ver=... argument is required\n")
			exit(1)
		flags=frozenset(args.get("flags",""))
		encrypt="e" in flags or "pass" in args or "rounds" in args
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
		tar2ab_main(
			stdin.buffer if infile_path is None else open(infile_path,"rb"),
			stdout.buffer if outfile_path is None else open(outfile_path,"wb"),
			version,
			(rounds,password) if encrypt else None,
			"c" in flags
		)
	stderr.write("unknown mode: %s\n"%mode)
	exit(1)

def abinfo_main(infile,outfile):
	version,compressed,encryption_info=read_header(infile)
	o=bytearray(b"flags=")
	if compressed:
		o.append(99)
	if encryption_info is not None:
		o.extend(b"e\nrounds=%d"%encryption_info[2])
	o.extend(b"\nver=%d\n"%version)
	outfile.write(o)
	exit(0)

def ab2tar_main(infile,outfile,password):
	version,compressed,encryption_info=read_header(infile)
	del version
	if encryption_info is None:
		data=bytearray(READ_BUF_SIZE)
		if compressed:
			from zlib import decompressobj
			decompressor=decompressobj(15)
			del decompressobj
			while True:
				l=infile.readinto(data)
				if not l:
					decompress_finish(outfile,decompressor)
				if l<READ_BUF_SIZE:
					decompress_into(outfile,decompressor,memoryview(data)[:l])
					decompress_finish(outfile,decompressor)
				decompress_into(outfile,decompressor,data)
		while True:
			l=infile.readinto(data)
			if not l:
				exit(0)
			if l<READ_BUF_SIZE:
				outfile.write(memoryview(data)[:l])
				exit(0)
			outfile.write(data)
	from Crypto.Protocol.KDF import PBKDF2
	from Crypto.Cipher import AES
	password_salt,master_key_checksum_salt,rounds,master_key_blob_iv,master_key_blob=encryption_info
	del encryption_info
	m=AES.new(
		PBKDF2(ask_pass() if password is None else password,password_salt,32,rounds),
		AES.MODE_CBC,iv=master_key_blob_iv
	).decrypt(master_key_blob)
	if m[0]!=16 or m[17]!=32 or m[50]!=32 or m[83:]!=b"\r\r\r\r\r\r\r\r\r\r\r\r\r":
		stderr.write("invalid decrypted master key blob\nwrong password?\n")
		exit(1)
	master_key=m[18:50]
	master_key_checksum=m[51:83]
	if PBKDF2(master_key,master_key_checksum_salt,32,rounds)!=master_key_checksum and PBKDF2(
		bytes("".join(chr(x|((x&128)*510)) for x in master_key),"utf8"),
		master_key_checksum_salt,32,rounds
	)!=master_key_checksum:
		stderr.write("bad master key checksum\nwrong password?\n")
		exit(1)
	decryptor=AES.new(master_key,AES.MODE_CBC,iv=m[1:17])
	del master_key_checksum,master_key,m,master_key_blob,master_key_blob_iv,rounds,master_key_checksum_salt,password_salt,AES,PBKDF2
	if compressed:
		from zlib import decompressobj
		decompressor=decompressobj(15)
		del decompressobj
		def notfinal(data):
			decryptor.decrypt(data,data)
			decompress_into(outfile,decompressor,data)
		def final(data):
			decryptor.decrypt(data,data)
			decompress_into(outfile,decompressor,unpad_memoryview(data))
			decompress_finish(outfile,decompressor)
	else:
		def notfinal(data):
			decryptor.decrypt(data,data)
			outfile.write(data)
		def final(data):
			decryptor.decrypt(data,data)
			outfile.write(unpad_memoryview(data))
			exit(0)
	prev_data=bytearray(READ_BUF_SIZE)
	l=infile.readinto(prev_data)
	if not l:
		raise Exception("eof on first read")
	if l<READ_BUF_SIZE:
		final(memoryview(prev_data)[:l])
	data=bytearray(READ_BUF_SIZE)
	while True:
		l=infile.readinto(data)
		if not l:
			final(prev_data)
		if l<READ_BUF_SIZE:
			notfinal(prev_data)
			final(memoryview(data)[:l])
		notfinal(prev_data)
		prev_data,data=data,prev_data

def tar2ab_main(infile,outfile,version,encrypt_info,compress):
	if encrypt_info:
		from binascii import b2a_hex
		from Crypto.Protocol.KDF import PBKDF2
		from Crypto.Cipher import AES
		from Crypto.Random import get_random_bytes
		rounds,password=encrypt_info
		rb=get_random_bytes(192)
		master_key=bytes(map((127).__and__,rb[:32]))
		password_salt=rb[32:96]
		master_key_checksum_salt=rb[96:160]
		master_key_blob_iv=rb[160:176]
		data_iv=rb[176:]
		rounds,password=encrypt_info
		del rb,get_random_bytes,encrypt_info
		outfile.write(b"ANDROID BACKUP\n%d\n%x\nAES-256\n%b\n%b\n%d\n%b\n%b\n"%(
			version,compress,
			b2a_hex(password_salt).upper(),
			b2a_hex(master_key_checksum_salt).upper(),
			rounds,
			b2a_hex(master_key_blob_iv).upper(),
			b2a_hex(AES.new(
				PBKDF2(password,password_salt,32,rounds),
				AES.MODE_CBC,iv=master_key_blob_iv
			).encrypt(b"\x10%b %b %b\r\r\r\r\r\r\r\r\r\r\r\r\r"%(
				data_iv,master_key,
				PBKDF2(master_key,master_key_checksum_salt,32,rounds)
			))).upper()
		))
		encryptor=AES.new(master_key,AES.MODE_CBC,iv=data_iv)
		del password,rounds,master_key_blob_iv,master_key_checksum_salt,password_salt,master_key,AES,PBKDF2,b2a_hex,version
		data=bytearray(READ_BUF_SIZE)
		if compress:
			from zlib import compressobj
			compressor=compressobj(9,8,15,9,0)
			del compressobj
			outdata=bytearray()
			while True:
				l=infile.readinto(data)
				if l<READ_BUF_SIZE:
					outdata.extend(compressor.compress(memoryview(data)[:l]))
					outdata.extend(compressor.flush())
					pad=16-(15&len(outdata))
					outdata.extend(b"%c"%pad*pad)
					encryptor.encrypt(outdata,outdata)
					outfile.write(outdata)
					exit(0)
				outdata.extend(compressor.compress(data))
				s=len(outdata)&-16
				m2=memoryview(outdata)
				m=m2[:s]
				encryptor.encrypt(m,m)
				outfile.write(m)
				m.release()
				m2.release()
				del outdata[:s]
		while True:
			l=infile.readinto(data)
			if l<READ_BUF_SIZE:
				pad=16-(15&l)
				for i in range(l,l+pad):
					data[i]=pad
				data=memoryview(data)[:l+pad]
				encryptor.encrypt(data,data)
				outfile.write(data)
				exit(0)
			encryptor.encrypt(data,data)
			outfile.write(data)
	outfile.write(b"ANDROID BACKUP\n%d\n%x\nnone\n"%(
		version,compress
	))
	del encrypt_info,version
	data=bytearray(READ_BUF_SIZE)
	if compress:
		from zlib import compressobj
		compressor=compressobj(9,8,15,9,0)
		del compressobj
		while True:
			l=infile.readinto(data)
			if l<READ_BUF_SIZE:
				outfile.write(compressor.compress(memoryview(data)[:l]))
				outfile.write(compressor.flush())
				exit(0)
			outfile.write(compressor.compress(memoryview(data)[:l]))
	while True:
		l=infile.readinto(data)
		if l<READ_BUF_SIZE:
			outfile.write(memoryview(data)[:l])
			exit(0)
		outfile.write(data)

def unpad_memoryview(m):
	pad=m[-1]
	if not 0<pad<17:
		raise Exception("bad padding amount")
	for i in range(-pad,-1):
		if m[i]!=pad:
			raise Exception("padding bytes not equal")
	return m[:-pad]

def decompress_into(file,decompressor,data):
	file.write(decompressor.decompress(data,MAX_DECOMPRESS_SIZE))
	if decompressor.eof:
		file.write(decompressor.flush())
		exit(0)
	while decompressor.unconsumed_tail:
		file.write(decompressor.decompress(decompressor.unconsumed_tail,MAX_DECOMPRESS_SIZE))
		if decompressor.eof:
			file.write(decompressor.flush())
			exit(0)

def decompress_finish(file,decompressor):
	file.write(decompressor.flush())
	if decompressor.eof:
		exit(0)
	raise Exception("finished reading data but no zlib eof")

def ask_pass():
	from getpass import getpass
	return bytes(getpass("enter password -> "),"ascii")

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

if __name__=="__main__":
	main()