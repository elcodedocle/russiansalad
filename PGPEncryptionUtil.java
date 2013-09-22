/** 
 * PGP encryption utility class by Gael Abadin (@gaelikun)
 * 
 * -----BEGIN RANT MESSAGE-----
 * I find the lack of well documented crypto libraries
 * **for Java** disturbing. I don't remember it taking
 * me so long to figure this out when I did it in Javascript.
 * Or PHP. (Now you know where I come from. Be scared.)
 * -----END RANT MESSAGE-----
 *
 * Pass an OpenPGP public key block to the constructor
 * of this class and then call encryptAndGetPGPMessage 
 * method with a String to encrypt and you will get
 * a String with the corresponding OpenPGP ascii armored 
 * message formatted as described in RFC4880 
 * (see http://tools.ietf.org/html/rfc4880#section-5.13)
 * 
 * based on http://goo.gl/0bHX7
 *
 * more info: http://www.bouncycastle.org 
 * 
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Iterator;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class PGPEncryptionUtil{
	
	// pick some sensible encryption buffer size
	private static final int BUFFER_SIZE = 4096;
	
	// encrypt the payload data using AES-256,
	// PGP uses a symmetric key to encrypt
	// data and uses the public key to encrypt the symmetric
	// key used on the payload.
	private static final int PAYLOAD_ENCRYPTION_ALG = PGPEncryptedData.AES_256;
	
	// various streams we're taking care of
	private ArmoredOutputStream armoredOutputStream;
	private OutputStream encryptedOut;
	private OutputStream compressedOut;
	private OutputStream literalOut;
	private ByteArrayOutputStream out = new ByteArrayOutputStream();
	
	private PGPPublicKey key;
	
	public PGPEncryptionUtil(String asciiArmoredPGPPublicKeyBlock) throws IOException {
		this.key=getPublicKey(asciiArmoredPGPPublicKeyBlock);
	}
	
	public PGPPublicKey getPublicKey(String asciiArmoredPGPPublicKeyBlock) throws IOException {
		InputStream is = new ByteArrayInputStream(asciiArmoredPGPPublicKeyBlock.getBytes("UTF-8"));
		PGPPublicKey pgpkey = getEncryptionKey(getKeyring(is));
		return pgpkey;
	}
	
	public String encryptAndGetPGPMessage(String stringToCode) throws IOException, PGPException {
		
		// write data out using "ascii-armor" encoding. This is the
		// normal PGP text output.
		this.armoredOutputStream = new ArmoredOutputStream(this.out);
		
		// create an encrypted payload and set the public key on the data
		// generator
		
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
			new JcePGPDataEncryptorBuilder(PAYLOAD_ENCRYPTION_ALG).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
		encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(this.key).setProvider("BC"));
		
		// open an output stream connected to the encrypted data generator
		// and have the generator write its data out to the ascii-encoding
		// stream
		this.encryptedOut = encGen.open(armoredOutputStream, BUFFER_SIZE);
		
		// compress data.  we are building layers of output streams.  we want to compress here
		// because this is "before" encryption, and you get far better compression on
		// unencrypted data.
		PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
		this.compressedOut = compressor.open(this.encryptedOut);
		
		// now we have a stream connected to
		// a data encryptor, which is connected to an ascii-encoder.
		// into that we want to write a PGP "literal" object, which is just a
		// named
		// piece of data (as opposed to a specially-formatted key, signature,
		// etc)
		PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
		this.literalOut = literalGen.open(compressedOut,
										  PGPLiteralDataGenerator.UTF8, "payload.file", new Date(),
										  new byte[BUFFER_SIZE]);
		
		// write something
		PrintWriter pw = new PrintWriter(this.literalOut);
		pw.println(stringToCode);
		
		// flush the stream and close up everything
		pw.flush();
		this.close();
		String outputstring = new String(this.out.toByteArray(),"UTF-8");
		return outputstring;
	}
	
	private PGPPublicKeyRing getKeyring(InputStream keyBlockStream) throws IOException {
		PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(keyBlockStream));
		Object o = factory.nextObject();
		if (o instanceof PGPPublicKeyRing) {
			return (PGPPublicKeyRing)o;
		}
		throw new IllegalArgumentException("Input text does not contain a PGP Public Key");
	}
	
	private PGPPublicKey getEncryptionKey(PGPPublicKeyRing keyRing) throws IOException {
		if (keyRing == null)
			return null;
		
		// iterate over the keys on the ring, look for one
		// which is suitable for encryption.
		Iterator<?> keys = keyRing.getPublicKeys();
		PGPPublicKey key = null;
		while (keys.hasNext()) {
			key = (PGPPublicKey)keys.next();
			if (key.isEncryptionKey()) {
				return key;
			}
		}
		return key;
	}
	
	/**
	 * Close the encrypted output writers.
	 */
	private void close() throws IOException {
		// close the literal output
		literalOut.close();
		
		// close the compressor
		compressedOut.close();
		
		// close the encrypted output
		encryptedOut.close();
		
		// close the armored output
		armoredOutputStream.close();
	}
	
}