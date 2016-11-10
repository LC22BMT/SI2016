package Bourdoux.Team;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by fabio on 03-11-2016.
 */
public class Chypher_Functions {

    private static final int AES_BLOCK_SIZE = 16;

    public Chypher_Functions() {
    }



    public static byte[]  enc_CTR (ByteArrayInputStream bIn,SecretKeySpec  key , byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        CipherInputStream cIn = new CipherInputStream(bIn, cipher);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = cIn.read()) >= 0) {
            bOut.write(ch);
        }

        return bOut.toByteArray();

    }

    public static String  denc_CTR (  byte[] ciphertext, SecretKeySpec key , byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
        cOut.write(ciphertext);
        cOut.close();
        return new String(bOut.toByteArray());

    }



    public static final void jumpToOffset(final Cipher c, final SecretKey aesKey, final IvParameterSpec iv, final long offset) {
        if (!c.getAlgorithm().toUpperCase().startsWith("AES/CTR")) {
            throw new IllegalArgumentException( "Invalid algorithm, only AES/CTR mode supported");
        }

        if (offset < 0) {
            throw new IllegalArgumentException("Invalid offset");
        }

        final int skip = (int) (offset % AES_BLOCK_SIZE);
        final IvParameterSpec calculatedIVForOffset = calculateIVForOffset(iv,
                offset - skip);
        try {
            c.init(Cipher.ENCRYPT_MODE, aesKey, calculatedIVForOffset);
            final byte[] skipBuffer = new byte[skip];
            c.update(skipBuffer, 0, skip, skipBuffer);
            Arrays.fill(skipBuffer, (byte) 0);
        } catch (ShortBufferException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);

        }
    }

    private static IvParameterSpec calculateIVForOffset(final IvParameterSpec iv, final long blockOffset) {
        final BigInteger ivBI = new BigInteger(1, iv.getIV());
        final BigInteger ivForOffsetBI = ivBI.add(BigInteger.valueOf(blockOffset/AES_BLOCK_SIZE));

        final byte[] ivForOffsetBA = ivForOffsetBI.toByteArray();
        final IvParameterSpec ivForOffset;
        if (ivForOffsetBA.length >= AES_BLOCK_SIZE) {
            ivForOffset = new IvParameterSpec(ivForOffsetBA, ivForOffsetBA.length - AES_BLOCK_SIZE,
                    AES_BLOCK_SIZE);
        } else {
            final byte[] ivForOffsetBASized = new byte[AES_BLOCK_SIZE];
            System.arraycopy(ivForOffsetBA, 0, ivForOffsetBASized, AES_BLOCK_SIZE
                    - ivForOffsetBA.length, ivForOffsetBA.length);
            ivForOffset = new IvParameterSpec(ivForOffsetBASized);
        }

        return ivForOffset;
    }



}
