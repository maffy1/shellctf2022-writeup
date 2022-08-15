def xor(msg, key):
    o = ''
    for i in range(len(msg)):
        o += chr((msg[i]) ^ (key[i % len(key)]))
    print(o)
    return 
 
# with open('message', 'r') as f:
#     msg = ''.join(f.readlines()).rstrip('\n')
 
# with open('key', 'r') as k:
#     key = ''.join(k.readlines()).rstrip('\n')
    
# assert key.isalnum() and (len(key) == 9)
# assert 'SHELL' in msg
 
# with open('encrypted', 'w') as fo:
#     fo.write(xor(msg, key))

with open('encrypted','rb+') as f:
    s=f.read()
msg=[]
for i in s:
    msg.append(i)
xorkey='SHELL{A2o'
key1=[]
for i in range(len(xorkey)):
    key1.append((msg[i])^ord(xorkey[i]))
print(bytes(key1))
key='XORISCOOL'
for i in range(len(key)):
    key1[i]=ord(key[i])
xor(msg,key1)
