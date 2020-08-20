# Encryption-Decryption-txt-files-assembly-project

## The user is demanded:
### *the file's location
### *the action to be performed ( encryption/decryption-  1st/2nd algorithm)
### *a key

## **First algorithm** - the key must be an integer between 0 and 7
### 1.Every ASCII character is turned into his 2's complement
### 2.To this value is performed ror with the number of bits specified in the key
### 3.Decryption consists of the reverse operations

## **Second algoritm** - the key is a string of 8 characters
### 1.Every 10 bytes are converted to 2's complement
### 2.It is performed xor between these 10 bytes and the key ( for the remaining 2 bytes, the key repeats)
### 3.Decryption consists of the reverse operations


## This was a homework I received at university.
