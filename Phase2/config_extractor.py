import os, string, shutil,re
import pefile
import re
import badstr
def decrypt_1(a, size):
    decrypted_value = b""
    for i, byte in enumerate(a):
        if i >= size:
        	decrypted_value += (byte).to_bytes(length = 1,byteorder="little", signed=False)
        	continue
        tmp2 = ((byte - 122) & (2**8-1)) ^ 96
        decrypted_value += (tmp2).to_bytes(length = 1,byteorder="little", signed=False)
    #print(decrypted_value)
    return decrypted_value
def decrypt_2(a, size):
    key_list = [134,104,102,96,1,3,5,7,9]
    counter = 0
    decrypted_value = b""
    for i, byte in enumerate(a):
        if i >= size:
        	decrypted_value += (byte).to_bytes(length = 1,byteorder="little", signed=False)
        	continue
        tmp2 = (byte & 255) ^ key_list[counter]
        decrypted_value += (tmp2).to_bytes(length = 1,byteorder="little", signed=False)
        counter += 1
        if counter == 9:
            counter = 0
    #print(decrypted_value)
    return decrypted_value
def extract_str(s_a, d_a, d_s, tmp_2, title, pe):
	result = b''
	print()
	if (s_a >= d_a and s_a <= (d_a + d_s)):
	    for byte in tmp_2[s_a - d_a:]:
	    	if byte:
	    		result += (byte).to_bytes(length = 1,byteorder="little", signed=False)
	    	else:
	    		break
	else:
	    data_dump = pe.get_data(s_a - pe.OPTIONAL_HEADER.ImageBase, d_s)
	    for byte in data_dump:
	    	if byte:
	    		result += (byte).to_bytes(length = 1,byteorder="little", signed=False)
	    	else:
	    		break
	print(title, ": ",  result.decode('gbk', errors = 'ignore'))
print("--------------------------------------")
print("File Properties: ")
print("--------------------------------------")
PEfile_Path = input("File Name -->  ")
pe = pefile.PE(PEfile_Path )
print("Path:", PEfile_Path)
# Check if it is a 32-bit or 64-bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("This is a 32-bit binary")
else:
    print("This is a 64-bit binary")
print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
)
print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))
print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))

# Decrypt the dll file

print("--------------------------------------")
print("Decryption Report: ")
print("--------------------------------------")
data_virtual_addr = 0
data_size = 0
text_virtual_add = 0
text_size = 0
image_base_addr = pe.OPTIONAL_HEADER.ImageBase
for i, section in enumerate(pe.sections):
    if section.Name == b'.data\x00\x00\x00':
        data_virtual_addr = section.VirtualAddress
        data_size = section.Misc_VirtualSize
    elif section.Name == b'.text\x00\x00\x00':
        text_virtual_addr = section.VirtualAddress
        text_size = section.Misc_VirtualSize

#data_dump = pe.get_data(int("0x1000b3c0", 0) - image_base_addr, int("0x3f4",0))
text_dump = pe.get_data(text_virtual_addr, text_size)
#tmp = decrypt_1(data_dump)
#print(tmp)
#tmp_2 = decrypt_2(tmp)
#print(tmp_2.decode('gbk', errors = 'ignore'))
# Signature for Service
a = b'\x8b\x44..\xa3....\x8b\x44..\x83\xf8.\x75.\x56\xB9....\xE8....\x8B\x35....\x56\x68....\x68....\xE8....\x56\x68....\x68....\xE8....\x83\xC4.\xB8.....\xC2\x0C\x00'

for m in re.finditer(a, text_dump):
    # print('%02d-%02d: %s' % (m.start(), m.end(), m.group(0)))
    decrypt_size = pe.get_data(text_virtual_addr + m.start() + int("0x25", 0), 4)
    decrypt_addr = pe.get_data(text_virtual_addr + m.start() + int("0x2a", 0), 4)
    print("Decryption Size: ", int.from_bytes(decrypt_size, "little"))
    print("Start Address of Decryption: ", decrypt_addr[::-1])
d_a = int.from_bytes(decrypt_addr, "little")
d_s = int.from_bytes(decrypt_size, "little")
data_dump = pe.get_data(d_a - image_base_addr, d_s)
s = int.from_bytes(decrypt_size, "little")
tmp = decrypt_1(data_dump, s)

tmp_2 = decrypt_2(tmp, s/3)
#print(tmp_2.decode('gbk', errors = 'ignore'))

Service_Pattern = b'\x50\x68....\xFF.....\x8D......\x68....\x51\x8D......\x68....\x52\xFF.....\x83..\x8D......\x68....\x50\xFF.....\x8D......\x68....\x51\xFF.....\x8D......\x6A.\x8D......\x52\x50\xFF.....\x8D......\x51\xE8....\x83..\x85.\x75.\x8D......\x8D......\x52\x50\xFF.....\x83..\x8B.....'

for m in re.finditer(Service_Pattern, text_dump):
    addr = pe.get_data(text_virtual_addr + m.start() + int("0x14", 0), 4)
    print("\nService Name Address: ", addr[::-1])
s_a = int.from_bytes(addr, "little")

# Fetch Configuration

print("--------------------------------------")
print("Configuration Report: ")
print("--------------------------------------")
print("------------------------")
print("Service Related: ")
print("------------------------")
extract_str(s_a, d_a, d_s, tmp_2, "Service", pe)


Service_Pattern = b'\x8B...\x56\x50\x68....\x68....\x68....\xE8....\x68....\x68....\x6A.\x8B\xF0\xE8....\x68....\x68....\x6A.\xE8....\x83..\x8B..\xC2..'
for m in re.finditer(Service_Pattern, text_dump):
    addr = pe.get_data(text_virtual_addr + m.start() + int("0x07", 0), 4)
    print(addr)
    print("\nService String Address: ", addr[::-1])
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "Description", pe)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x0C", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "Display_name", pe)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x11", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "Service_name", pe)
Service_Pattern = b'\xA1....\x56\x68....\x50\x68....\x8D......\x68....\x51\xFF.....\x83..'
for m in re.finditer(Service_Pattern, text_dump):
    addr = pe.get_data(text_virtual_addr + m.start() + int("0x0D", 0), 4)
    
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "Target Host IP", pe)

addr = pe.get_data(text_virtual_addr + m.start() + int("0x01", 0), 4)
s_a = int.from_bytes(addr, "little")
result = b''
for byte in tmp_2[s_a - d_a:]:
	if byte:
	    result += (byte).to_bytes(length = 1,byteorder="little", signed=False)
	else:
	    break
print("\nPort Number: ", int.from_bytes(result, "little"))
print("------------------------")
print("INI Related: ")
print("------------------------")
Service_Pattern = b'\x8B...\x56\x50\x68....\x68....\x68....\xE8....\x68....\x68....\x6A.\x8B\xF0\xE8....\x68....\x68....\x6A.\xE8....\x83..\x8B..\xC2..'
for m in re.finditer(Service_Pattern, text_dump):
    addr = pe.get_data(text_virtual_addr + m.start() + int("0x07", 0), 4)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x1B", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "INI Key", pe)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x20", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "INI Value", pe)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x33", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "INI Value", pe)


INI_Pattern = b'\x81.....\x53\x56\x57\xB9....\x33.\x8D...\xC6....\x68........\xAA\x8D...\x50\xFF.....\xBF....\x83..\x33.\x8D.....\xF7.\x2B.\x8B.\x8B.\x8B.\x83....\x8B.\x4F\xC1....\x8B......\x8B.\x83..\x8D.....\x8B......\x50\x51\x52\x68....\xFF........\x81.....\xC3'
for m in re.finditer(INI_Pattern, text_dump):
    addr = pe.get_data(text_virtual_addr + m.start() + int("0x2F", 0), 4)
    print("\nINI File Name Address: ", addr[::-1])
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "INI File Name", pe)
addr = pe.get_data(text_virtual_addr + m.start() + int("0x72", 0), 4)
s_a = int.from_bytes(addr, "little")
extract_str(s_a, d_a, d_s, tmp_2, "INI Section Name", pe)
csv = open("String_Analysis.csv",'w')
print("------------------------")
print("List All String Decoded In GBK: ")
print("------------------------")
# Print all string
s_a = data_virtual_addr+pe.OPTIONAL_HEADER.ImageBase
while(1):
	if  (s_a >= data_virtual_addr+data_size+pe.OPTIONAL_HEADER.ImageBase):
	    break
	result = b""
	if (s_a >= d_a and s_a <= (d_a + d_s)):
	    s_a += 1
	    for byte in tmp_2[s_a - d_a:]:
	    	s_a += 1
	    	if byte:
	    		result += (byte).to_bytes(length = 1,byteorder="little", signed=False)
	    	else:
	    		break
	else:
	    data_dump = pe.get_data(s_a - pe.OPTIONAL_HEADER.ImageBase, d_s)
	    s_a += 1
	    for byte in data_dump:
	    	s_a += 1
	    	if byte:
	    		result += (byte).to_bytes(length = 1,byteorder="little", signed=False)
	    	else:
	    		break
	if(len(result) > 4):
	    print(result.decode('gbk', errors = 'ignore'))
badstr.get(PEfile_Path, csv)