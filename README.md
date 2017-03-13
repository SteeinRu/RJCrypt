# RJCrypt - Library
AES implementation of symmetric key encryption Rijndael using

## Using

### Declaring the main class

```c#
RJCrypt rj = new RJCrypt();
```

### Encrypt a string using Rijndael AES 256-bit

```c#
string password = "eUCX6V54eTr?C8M";  // The password to encrypt the data with
string plaintext = "Text"; // The string to encrypt

// Encrypt the string
string ciphertext = rj.Encrypt(plaintext, password, RJCrypt.Common.KeySize.Aes256);

// Decrypt the string
plaintext = rj.Decrypt(ciphertext, password, RJCrypt.Common.KeySize.Aes256);
```

### Encrypt a string using Authenticated Encryption (AE)
```c#
string password = "eUCX6V54eTr?C8M";  // The password to encrypt the data with
string plaintext = "Text"; // The string to encrypt

// Encrypt the string
string aeCiphertext = rj.Encrypt(plaintext, password, RJCrypt.Common.KeySize.Aes256);

// Decrypt the string
plaintext = rj.Decrypt(aeCiphertext, password, RJCrypt.Common.KeySize.Aes256);
```

### Encrypt a file using Rijndael AES 256-bit
```c#
string password = "eUCX6V54eTr?C8M";            // The password to encrypt the file with
string plaintextFile = @"D:\Photo.png";         // The file to encrypt
string ciphertextFile = @"D:\ProtectedFiles";   // The encrypted file (extension unnecessary)

// Encrypt the file
rj.Encrypt(plaintextFile, ciphertextFile, password, RJCrypt.Common.KeySize.Aes256);

// Decrypt the file
rj.Decrypt(ciphertextFile, plaintextFile, password, RJCrypt.Common.KeySize.Aes256);
```

