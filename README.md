# AES Encryption API
AES encryption API using ECB, CBC and CFB as its modes of operation. The API takes a Bitmap image as its input, then encrypts the file contents using a fixed key. The encrypted output is then stored as the body of a JPG image file. The API is able to generate the output JPG file using three different modes of operation, which are using Electronic Codebook (ECB), Cipher-Block Chaining (CBC) and Cipher Feedback (CFB).

## Geting started
This project requires the Java SDK in order to compile the program.

### Compiling
The program can be compiled by using the following command:

```
javac aesEncryptionAPI.java
```

### Using the program
The main method is set up to demonstrate its functionality, and can be used by using the following command:

```
java aesEncryptionAPI <Name of input image file in .bmp format>
```

## Description
This API allows you to create a secret key using the generateKey() function, this secret key is then stored in a KeyStore file. A secret key can be loaded using the getKey() function, this takes a key from a KeyStore file, using the specified passwords.

The function createIv() can be used to create an initialization vector, which is then saved in a plaintext file. The function loadIv() can be used to load an initialization vector from a file, this function then returns the initialization vector so that it can be used later.

In order to encrypt an image file using this API, the getRGB() function needs to be called to get all of the RGB values of that image in a byte array. Then the functions encryptECB(), encryptCBC(), and encryptCFB() can be called to encrypt the byte array of RGB values. These functions return an encrypted byte array of these RGB values. Then the function createRGB() can be called, which creates an image of a given byte array. In this case, the encrypted byte array of the RGB values is passed to it. This function then creates a new image using that byte array.

The function decryptECB(), decryptCBC(), and decryptCFB() can be called to decrypt the byte array of encrypted RGB values. This function returns the byte array of RGB values, which will be the same as the byte array of RGB values that was first created using the getRGB() function. Then the function createRGB() can be called again, which creates an image using the decrypted RBG byte array. This image is the same as the original image.

When an exception occurs in one of the methods, an error message is displayed. It doesn’t not exit the program, as its an API and whoever is using it should be able to do whatever they want when an exception is thrown.

## Methods
### generateKey
This function takes the name of the file of where to store the KeyStore, a password for the whole KeyStore, as well as a password for the entry in the KeyStore which holds the secret key. The function creates a new KeyStore, generates a new secret key and adds it as an entry in the KeyStore. It then saves the KeyStore to the specified file location. A KeyStore is used to securely store the secret key.

### getHeight
This function takes the file location of an image and returns the height of that image. This function is required because the height of different images is needed in several other functions.
getWidth
This function takes the file location of an image and returns the width of that image. This function is required because the width of different images is needed in several other functions.

### getRGB
This function takes an image as the input file and reads the image. The function then creates a byte array. The first three entries of the byte array are the RGB values of the first pixel of the image. The function then goes through the whole image, adding the RGB values of each pixel to the byte array. The function then returns that byte array with the RGB values.

### createRGB
This function takes a byte array as the input and does the opposite as the function above. This function turns the byte array back into an image. It achieves this by going through every pixel in the image, and for each pixel getting the red, green and blue values from the byte array to recreate the color. The function then sets the RGB value for that pixel on the new image. After going through the whole image, the function saves the image to the specified file location. The function takes the file location of the original image, so that it can get the original width and height of the image in order to recreate the image.

### createIv
This function creates a new initialization vector (iv). Then an IvParameterSpec is created, which is needed for the cipher. The iv is stored to a file, so that it can be used later.
getKey
This function loads a key from a KeyStore file, for example one that was created using the function described above (generateKey). It gets the secret key from the KeyStore using the given password for the KeyStore, as well as the password for the KeyStore entry containing the secret key. The function then returns this secret key.

### encryptECB
This function encrypts a byte array, given a secret key. A cipher object is created, which handles the encryption and decryption. Here the mode of operation is specified, in this case being Electronic CodeBook, as well as the padding. After encrypting the byte array, the function returns the encrypted byte array.

### encryptCBC
This function performs the same thing as the function described above, however this time it uses Cipher-Block Chaining as its mode of operation. Furthermore, it takes an initialization vector, which is needed for CBC. When initializing the cipher, this iv is given to the cipher object as well as the secret key.

### encryptCFB
This function performs the same thing as the function described above, however this time it uses Cipher Feedback as its mode of operation. Furthermore, it also takes an initialization vector, which is needed for CFB. When initializing the cipher, this iv is given to the cipher object as well as the secret key.

### decryptECB
This function decrypts a given encrypted byte array, using Electronic Codebook as its mode of operation. This function is given the encrypted byte array and the secret key and returns the decrypted byte array. When initializing the cipher, the cipher is set to DECRYPT_MODE instead of ENCRYPT_MODE as in the three functions above.

### decryptCBC
This function performs the same thing as the function described above, however this time is uses Cipher-Block Chaining as its mode of operation.
### decryptCFB
This function performs the same thing as the function described above, however this time is uses Cipher Feedback as its mode of operation.
### loadIv
This function takes the file location of an initialization vector, for example like the one that was created using the function described above (createIv). The function creates a new IvParameterSpec from the contents of the specified file. It then returns the iv so that it can be used for encrypting and decrypting.

## Differences between ECB, CBC and CFB
AES encrypts in blocks of 128 bits, Electronic Codebook uses the same unaltered key on every block. The problem with this approach is that identical plaintext blocks will be encrypted to identical ciphertext blocks, as the key to encrypt those blocks is the same. From Figure 1, you can see which areas have the same color.

When it comes to Cipher-Block Chaining, it XORs the current plaintext block with the previous blocks ciphertext and the previous plaintext block. The very first block is encrypted using an initialization vector. This iv is public and random and should only be used once.

Cipher Feedback is very similar to CBC, but it turns a cipher block into a self-synchronizing stream
cipher. When part of the message doesn’t get transmitted, the whole message isn’t lost.

The impact that the different modes have can be seen from the output images, as the image encrypted
with ECB is still recognizable, while the images from the other two modes cannot be recognized. The
images encrypted with CFB and CBC look like random noise, and there is no way to tell what the
original image looked like.

## Demonstration
The demonstration takes as input a Bitmap image file, and outputs three encrypted JPG files using the three different modes of operation. It also outputs an IV file, and a keystore file with the secret key. 

### Input image
![Input](https://raw.githubusercontent.com/alexbakx/aesEncryptionAPI/master/inputImage.bmp)

### ECB output JPG of the input image
![ECB](https://github.com/alexbakx/aesEncryptionAPI/blob/master/inputImageECBEncrypted.jpg)

### CFB output JPG of the input image
![CFB](https://github.com/alexbakx/aesEncryptionAPI/blob/master/inputImageCFBEncrypted.jpg)

### CBC output JPG of the input image
![CBC](https://github.com/alexbakx/aesEncryptionAPI/blob/master/inputImageCBCEncrypted.jpg)

