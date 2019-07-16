import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.awt.Color;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;
import java.security.UnrecoverableEntryException;
import javax.crypto.IllegalBlockSizeException; 
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.NoSuchPaddingException;

public class aesEncryptionAPI {
    
    public static void main(String[] args) {
	if (args.length == 1){
	    try {
		String inFile = args[0];

		//Code to generate a new secret key
		SecretKeySpec generatedKey = generateKey("keystore.ks", "123test", "helloworld", "SecretKey");

		//Code to load a secret key from a file
		SecretKeySpec loadedKey = getKey("keystore.ks", "123test", "helloworld", "SecretKey");

		//Code to create a new initialization vector
		IvParameterSpec generatedIv = generateIv("iv.txt");
		
		//Code to load an iv from a file
		IvParameterSpec loadedIv = loadIv("iv.txt");

		//Remove the extension from the file name
		String fileName = inFile.split("\\.")[0];

		//Specify the file names for the encrypted images and the decrypted image
		String encryptedFileECB = fileName + "ECBEncrypted.jpg";
		String encryptedFileCBC = fileName + "CBCEncrypted.jpg";
		String encryptedFileCFB = fileName + "CFBEncrypted.jpg";
		String outFile = fileName + "Decrypted.bmp";

		//Fixed secret key for the purpose of this demonstration
		byte[] keyByte = "770A8A65DA156D24EE2A093277530142".getBytes(StandardCharsets.UTF_8);
		SecretKeySpec skey = new SecretKeySpec(keyByte, "AES");

		//Get byre array containing RGB values of input image
		byte[] content = getRGB(inFile);


		//Encrypt the input image using the 3 different modes of operation
		byte[] encryptedCFB = encryptCFB(skey, loadedIv, content);
		byte[] encryptedCBC = encryptCBC(skey, loadedIv, content);
		byte[] encryptedECB = encryptECB(skey, content);

		//Create images from the encrypted byte arrays
		createImage(encryptedCFB, encryptedFileCFB, inFile, "jpg");
		System.out.println(encryptedFileCFB + " successfully created");
		createImage(encryptedCBC, encryptedFileCBC, inFile, "jpg");
		System.out.println(encryptedFileCBC + " successfully created");
		createImage(encryptedECB, encryptedFileECB, inFile, "jpg");
		System.out.println(encryptedFileECB + " successfully created");

		//Decrypt the image using one of the modes of operation
		byte[] decryptedCFB = decryptCFB(skey, loadedIv, encryptedCFB);

		//Create an image from the decrypted byte array, this will be the same as the input image
		createImage(decryptedCFB, outFile, inFile, "bmp");
		System.out.println(outFile + " successfully created");

		System.out.println("Done!");

	    } catch (Exception e){
		e.printStackTrace();
	    }
	} else {
	    System.err.println("Invalid input. Usage: java ExtendedExperimentalAPI <fileName>");
	}
    }


    /**
     * Generates a secret key and stores in a KeyStore 
     * @param name of output file
     * @param password for the whole keyStore
     * @param password for the KeyStore entry
     * @return nothing, it simply saves the KeyStore to a file
     */
    public static SecretKeySpec generateKey(String keyFile, String keyStorePassword, String keyStoreEntryPassword, String entryAlias){
	try {
	    //Create a new KeyStore
	    KeyStore skeyKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());

	    //Create a password for the KeyStore and the entry in the KeyStore
	    char[] keyStorePasswordArray = keyStorePassword.toCharArray();
	    char[] keyStoreEntryPasswordArray = keyStoreEntryPassword.toCharArray();
	    KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyStoreEntryPasswordArray);

	    //Need to load the KeyStore instance before it can be used
	    skeyKeyStore.load(null, keyStorePasswordArray);

	    //Generate a new secret key
	    KeyGenerator kgen = KeyGenerator.getInstance("AES");
	    SecretKey skey = kgen.generateKey();

	    //Converts the secret key to a secret key spec so we can return it and use it
	    SecretKeySpec skeySpec = new SecretKeySpec(skey.getEncoded(), "AES");

	    //Add the secret key to the KeyStore as an entry
	    KeyStore.SecretKeyEntry skeyEntry = new KeyStore.SecretKeyEntry(skey);
	    skeyKeyStore.setEntry(entryAlias, skeyEntry, entryPassword);

	    //Save the KeyStore to the specified location
	    try (FileOutputStream out = new FileOutputStream(keyFile)){
		skeyKeyStore.store(out, keyStorePasswordArray);
	    } catch (Exception e){
		e.printStackTrace();
	    }

	    //Returns the secret key spec
	    return skeySpec;
	    
	} catch (KeyStoreException kse){
	    System.err.println("Failed to get secret key entry.");
	} catch (IOException ioe){
	    System.err.println("KeyStore file woudn't load.");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (CertificateException ce){
	    System.err.println("There was a problem with a certificate.");
	}

	return null;
    }

    /**
     * Gets the height for a specified image
     * @param input image for which to find the height
     * @returns height of the image
     */
    public static int getHeight(String inputFile){
	try {
	    //Create new buffered image from file
	    File input = new File(inputFile);
	    BufferedImage img = ImageIO.read(input);
	    
	    //Calculate height and return it
	    int height = img.getHeight();
	    return height;
	    
        } catch (IOException ioe){
	    System.err.println("Image not found");
	} catch (NullPointerException npe){
	    System.err.println("Invalid file type");
	}
	
	return 0;
    }

    /**
     * Gets the width for a specified image
     * @param input image for which to find the width
     * @returns width of the image
     */
    public static int getWidth(String inputFile){
	try {
	    //Create new buffered image from file
	    File input = new File(inputFile);
	    BufferedImage img = ImageIO.read(input);

	    //Calculate width and return it
	    int width = img.getWidth();
	    return width;
	    
	} catch (IOException ioe){
	    System.err.println("Image not found");
	} catch (NullPointerException npe){
	    System.err.println("Invalid file type");
	}
	
	return 0;
    }

    /**
     * Gets a byte array of the RGB values of an image
     * @param input image for which to find the RGB values
     * @returns byte array of RGB values
     */
    public static byte[] getRGB(String inputFile){
        int RGB_SIZE = 3;
        int BSHIFT = 0xFF;
	BufferedImage img;
	int width;
	int height;
	try {
	    //Read image and get width and height
	    File input = new File(inputFile);
	    img = ImageIO.read(input);
	    width = img.getWidth();
	    height = img.getHeight();

	    //Declare byte array for every RGB value for every pixel in the image
	    //Every pixel has 3 values (RGB), times the width and height
	    byte[] t = new byte[width * height * RGB_SIZE];
	    int index = 0;

	    //Loop through every pixel in the image and add the RGB values to the byte array
	    for (int i = 0; i < height; i++){
		for (int j = 0; j < width; j++){
		    //Get RGB values for that pixel
		    Color c = new Color(img.getRGB(j, i));
		    byte r = (byte) c.getRed();
		    byte g = (byte) c.getGreen();
		    byte b = (byte) c.getBlue();

		    //Add RGB values to the byte array
		    t[index++] = r;
		    t[index++] = g;
		    t[index++] = b;
		}
	    }
	    //Return the byte array
	    return t;

	} catch (IOException ioe){
	    System.err.println("File not found");
	} catch (NullPointerException npe){
	    System.err.println("Invalid file type");
	}
	
	return null;
    }

    /**
     * Given a byte array of RGB values, turns that array back into an image
     * @param byte array of RGB values to be turned into an image
     * @param name of file to save the image to
     * @param name of the original image file
     * @param file type of the output image
     * @returns nothing, it simply saves the image
     */
    public static void createImage(byte[] content, String fileOut, String originalImage, String fileType){
        int RGB_SIZE = 3;
        int BSHIFT = 0xFF;
	try {
	    //Get width and height of original image in order to recreate it
	    int height = getHeight(originalImage);
	    int width = getWidth(originalImage);

	    //Create new blank buffered image
	    BufferedImage newImage = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
	    int index = 0;

	    //Loop through every pixel of the new blank image
	    for (int i = 0; i < height; i ++){
		for (int j = 0; j < width; j++){
		    //Get the RGB values from the byte array
		    int r = content[index++] & BSHIFT;
		    int g = content[index++] & BSHIFT;
		    int b = content[index++] & BSHIFT;

		    //Set the pixel to the RGB values from the byte array
		    Color newColor = new Color(r, g, b);
		    newImage.setRGB(j, i, newColor.getRGB());
		}
	    }

	    //Save the new image file
	    File output = new File(fileOut);
	    ImageIO.write(newImage, fileType, output);
	    
	} catch (IOException ioe){
	    System.err.println("Image not found");
	} catch (IllegalArgumentException iae){
	    System.err.println("Width and height must be bigger than 0");
	} catch (NullPointerException npe){
	    System.err.println("Invalid file type");
	}
    }

    /**
     * Generates a new iv, returns it and saves it to a file
     * @param location of the file to save th iv to
     * @returns the iv
     */
    public static IvParameterSpec generateIv(String ivFile){
	//Generates a new iv
	SecureRandom srandom = new SecureRandom();
	byte[] iv = new byte[128/8];
	srandom.nextBytes(iv);
	IvParameterSpec ivspec = new IvParameterSpec(iv);

	//Saves the iv to the specified file location
	try (FileOutputStream out = new FileOutputStream(ivFile)) {
	    out.write(iv);
	} catch (Exception e){
	    e.printStackTrace();
	}

	//Returns the iv
	return ivspec;
    }

    /**
     * Gets a secret key from a saved KeyStore file
     * @param name of the KeyStore file which has the secret key stored
     * @param password for the whole KeyStore
     * @param password for the entry holding the secret key in the KeyStore
     * @returns the secret key
     */
    public static SecretKeySpec getKey(String keyFileName, String keyStorePassword, String keyStoreEntryPassword, String entryAlias) {
	try {
	    //Creates a new KeyStore
	    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

	    //Converts the password to char arays so that we can use them to access the KeyStore
	    char[] keyStorePasswordArray = keyStorePassword.toCharArray();
	    char[] keyStoreEntryPasswordArray = keyStoreEntryPassword.toCharArray();

	    //Lodas the KeyStore from the specified file location
	    try (InputStream keyStoreData = new FileInputStream(keyFileName)){
		keyStore.load(keyStoreData, keyStorePasswordArray);
	    }

	    //Gets the entry containing the secret key
	    KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyStoreEntryPasswordArray);
	    KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(entryAlias, entryPassword);

	    //Gets the secret key from the entry, and converts it to a SecretKeySpec
	    SecretKey skeyEntry = keyEntry.getSecretKey();
	    SecretKeySpec skey = new SecretKeySpec(skeyEntry.getEncoded(), "AES");

	    //Returns the secret key spec
	    return skey;
	    
	} catch (KeyStoreException kse){
	    System.err.println("Failed to get secret key entry.");
	} catch (IOException ioe){
	    System.err.println("KeyStore file woudn't load.");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (CertificateException ce){
	    System.err.println("There was a problem with a certificate.");
	} catch (UnrecoverableEntryException ue){
	    System.err.println("Invalid entry password to recover the secret key.");
	}
	return null;
    } 

    /**
     * Encrypts a byte array using Electronic Codebook as its mode of operation
     * @param secret key used for encryption
     * @param byte array to be encrypted
     * @returns encrypted byte array
     */
    public static byte[] encryptECB(SecretKeySpec skey, byte[] content) {
	byte[] encrypted = null;
	try {
	    //Create cipher object used for encryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");

	    //Encrypt the byte array
	    ci.init(Cipher.ENCRYPT_MODE, skey);
	    encrypted = ci.doFinal(content);
	    
        } catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the encrypted byte array
	return encrypted;
    }

    /**
     * Encrypts a byte array using Cipher-Block Chaining as its mode of operation
     * @param secret key used for encryption
     * @param byte array to be encrypted
     * @returns encrypted byte array
     */
    public static byte[] encryptCBC(SecretKeySpec skey, IvParameterSpec iv, byte[] content) {
	byte[] encrypted = null;
	try {
	    //Create cipher object used for encryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");

	    //Encrypt the byte array
	    ci.init(Cipher.ENCRYPT_MODE, skey, iv);
	    encrypted = ci.doFinal(content);
	    
        } catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (InvalidAlgorithmParameterException iape){
	    System.err.println("Invalid or inappropriate encryption algorithm parameters");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the encrypted byte array
	return encrypted;
    }

    /**
     * Encrypts a byte array using Cipher Feedback as its mode of operation
     * @param secret key used for encryption
     * @param byte array to be encrypted
     * @returns encrypted byte array
     */
    public static byte[] encryptCFB(SecretKeySpec skey, IvParameterSpec iv, byte[] content) {
	byte[] encrypted = null;
	try {
	    //Create cipher object used for encryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/CFB/PKCS5Padding");

	    //Encrypt the byte array
	    ci.init(Cipher.ENCRYPT_MODE, skey, iv);
	    encrypted = ci.doFinal(content);

	} catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (InvalidAlgorithmParameterException iape){
	    System.err.println("Invalid or inappropriate encryption algorithm parameters");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the encrypted byte array
	return encrypted;
    }

    /**
     * Decrypts a byte array using Electronic Codebook as its mode of operation
     * @param secret key used for decryption
     * @param byte array to be decrypted
     * @returns decrypted byte array
     */
    public static byte[] decryptECB(SecretKeySpec skey, byte[] content){
	byte[] decrypted = null;
	try {
	    //Create cipher object used for decryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/ECB/PKCS5Padding");

	    //Decrypt the byte array
	    ci.init(Cipher.DECRYPT_MODE, skey);
	    decrypted = ci.doFinal(content);
	    
        } catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the decrypted byte array
	return decrypted;
    }

    /**
     * Decrypts a byte array using Cipher-Block Chaining as its mode of operation
     * @param secret key used for decryption
     * @param byte array to be decrypted
     * @returns decrypted byte array
     */
    public static byte[] decryptCBC(SecretKeySpec skey, IvParameterSpec iv, byte[] content){
	byte[] decrypted = null;
	try {
	    //Create cipher object used for decryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");

	    //Decrypt the byte array
	    ci.init(Cipher.DECRYPT_MODE, skey, iv);
	    decrypted = ci.doFinal(content);
	    
        } catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (InvalidAlgorithmParameterException iape){
	    System.err.println("Invalid or inappropriate decryption algorithm parameters");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the decrypted byte array
	return decrypted;
    }

    /**
     * Decrypts a byte array using Cipher Feedback as its mode of operation
     * @param secret key used for decryption
     * @param byte array to be decrypted
     * @returns decrypted byte array
     */
    public static byte[] decryptCFB(SecretKeySpec skey, IvParameterSpec iv, byte[] content){
	byte[] decrypted = null;
	try {
	    //Create cipher object used for decryption, specify mode of operation and padding
	    Cipher ci = Cipher.getInstance("AES/CFB/PKCS5Padding");

	    //Decrypt the byte array
	    ci.init(Cipher.DECRYPT_MODE, skey, iv);
	    decrypted = ci.doFinal(content);
	    
        } catch (IllegalArgumentException iae){
	    System.err.println("Byte array is empty");
	} catch (NoSuchAlgorithmException nsae){
	    System.err.println("Algorithm for recovering the secret key wasn't found.");
	} catch (InvalidKeyException ike){
	    System.err.println("Key wasn't found");
	} catch (IllegalBlockSizeException ibse){
	    System.err.println("Input is not a multiple of the block size (16 bytes for AES)");
	} catch (NoSuchPaddingException nspe){
	    System.err.println("The requested padding mechanism isn't available");
	} catch (InvalidAlgorithmParameterException iape){
	    System.err.println("Invalid or inappropriate decryption algorithm parameters");
	} catch (BadPaddingException bpe){
	    System.err.println("The data is not padded properly");
	}

	//Return the decrypted byte array
	return decrypted;
    }

    /**
     * Loads an iv from a specified file location
     * @param location of the file containing the iv
     * @returns the initialization vector (iv)
     */
    public static IvParameterSpec loadIv(String inFile){
	try {
	    //Read contents of the file and add to a byte array
	    byte[]iv = Files.readAllBytes(Paths.get(inFile));

	    //Create a new iv parameter spec from the byte array
	    IvParameterSpec ivspec = new IvParameterSpec(iv);

	    //Return the iv
	    return ivspec;
	    
	} catch (Exception e){
	    System.err.println("File not found");
	    return null;
	}
    }

}
