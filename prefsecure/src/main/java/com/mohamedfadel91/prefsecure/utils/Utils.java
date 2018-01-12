package com.mohamedfadel91.prefsecure.utils;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.mohamedfadel91.prefsecure.SecurityConstants;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by Fadel on 04/01/18.
 */

public class Utils {

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with device credentials within the last X seconds.
     *
     * @return true for success..
     */
    public static boolean createKey(@NonNull Context context,
                                    @NonNull String keyAlias) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                KeyStore keyStore = initKeyStore();
                if (!keyStore.containsAlias(keyAlias)) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_AES,
                                SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

                        // Set the alias of the entry in Android KeyStore where the key will appear
                        // and the constrains (purposes) in the constructor of the Builder
                        keyGenerator.init(new KeyGenParameterSpec.Builder(keyAlias,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                .build());
                        keyGenerator.generateKey();

                    } else {
                        Calendar start = new GregorianCalendar();
                        Calendar end = new GregorianCalendar();
                        end.add(Calendar.YEAR, 1);

                        KeyPairGenerator kpGenerator = KeyPairGenerator
                                .getInstance(SecurityConstants.KEY_ALGORITHM_RSA,
                                        SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

                        AlgorithmParameterSpec spec = new KeyPairGeneratorSpec.Builder(context)
                                // You'll use the alias later to retrieve the key.  It's a key for the key!
                                .setAlias(keyAlias)
                                // The subject used for the self-signed certificate of the generated pair
                                .setSubject(new X500Principal("CN=" + keyAlias))
                                // The serial number used for the self-signed certificate of the
                                // generated pair.
                                .setSerialNumber(BigInteger.valueOf(1337))
                                .setStartDate(start.getTime())
                                .setEndDate(end.getTime())
                                // Date range of validity for the generated pair.
                                .build();

                        kpGenerator.initialize(spec);
                        kpGenerator.generateKeyPair();
                    }
                }
                return true;
            } else {
                return false;
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                InvalidAlgorithmParameterException | KeyStoreException |
                CertificateException | IOException e) {
            return false;
        }
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which
     * only works if the user has just authenticated via device credentials.
     */
    @NonNull
    public static byte[] tryEncrypt(@NonNull String keyAlias, @NonNull
            byte[] input) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                KeyStore keyStore = initKeyStore();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias,
                            null);
                    if (secretKey == null) return input;

                    Cipher cipher = Cipher.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES + "/" +
                                    KeyProperties.BLOCK_MODE_CBC + "/"
                                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);

                    if (cipher != null) {
                        try {
                            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                            // build the initialization vector.  This example is all zeros, but it
                            // could be any value or generated using a random number generator.
                            byte[] iv = cipher.getIV();
                            byte[] result = cipher.doFinal(input);

                            byte[] output = new byte[16 + result.length];
                            System.arraycopy(iv, 0, output, 0, 16);
                            System.arraycopy(result, 0, output, 16, result.length);

                            return output;
                        }catch (Exception ex){
                            return input;
                        }

                    }
                } else {
                    KeyStore.Entry entry = getKeyPairFromKeyStore(keyStore, keyAlias);
                    if (entry == null) return input;

                    Cipher cipher = Cipher.getInstance(
                            SecurityConstants.KEY_ALGORITHM_RSA + "/" +
                                    SecurityConstants.BLOCK_MODE_ECB + "/"
                                    + SecurityConstants.ENCRYPTION_PADDING_PKCS1);

                    if (cipher != null) {
                        cipher.init(Cipher.ENCRYPT_MODE,
                                ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey());
                        return cipher.doFinal(input);
                    }

                }
                return input;
            } else {
                return input;
            }
        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException |
                NoSuchAlgorithmException ex) {
            return input;
        }
    }

    @NonNull
    private static KeyStore initKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(
                SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        keyStore.load(null);
        return keyStore;
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which
     * only works if the user has just authenticated via device credentials.
     */
    @NonNull
    public static byte[] tryDecrypt(@NonNull String keyAlias, @NonNull
            byte[] input) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                KeyStore keyStore = initKeyStore();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias,
                            null);
                    if (secretKey == null) return input;

                    Cipher cipher = Cipher.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES + "/" +
                                    KeyProperties.BLOCK_MODE_CBC + "/"
                                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);

                    if (cipher != null) {
                        try {
                            // getting the initialization vector from cipherText..
                            byte iv[] = new byte[16];
                            System.arraycopy(input, 0, iv, 0, 16);

                            IvParameterSpec ivspec = new IvParameterSpec(iv);
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

                            byte[] cipherInput = new byte[input.length - 16];
                            System.arraycopy(input, 16, cipherInput, 0, cipherInput.length);

                            return cipher.doFinal(cipherInput);
                        }catch (Exception ex){
                            return input;
                        }
                    }
                } else {
                    KeyStore.Entry entry = getKeyPairFromKeyStore(keyStore, keyAlias);
                    if (entry == null) return input;

                    Cipher cipher = Cipher.getInstance(
                            SecurityConstants.KEY_ALGORITHM_RSA + "/" +
                                    SecurityConstants.BLOCK_MODE_ECB + "/"
                                    + SecurityConstants.ENCRYPTION_PADDING_PKCS1);

                    if (cipher != null) {
                        cipher.init(Cipher.DECRYPT_MODE,
                                ((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
                        return cipher.doFinal(input);

                    }
                }
                return input;
            } else {
                return input;
            }
        } catch (IOException | UnrecoverableKeyException | KeyStoreException | CertificateException |
                NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException |
                NoSuchAlgorithmException ex) {
            return input;
        }
    }


    /**
     * return the Key-Pair (Private-Public) keys from KeyStore
     * @param keyStore the System KeyStore
     * @param keyAlias the alias of the key in the KeyStore
     * @return Key-Pair
     */
    @Nullable
    private static KeyStore.Entry getKeyPairFromKeyStore(@NonNull KeyStore keyStore,
                                                        @NonNull String keyAlias) {
        // Load the key pair from the Android Key Store
        KeyStore.Entry entry;
        try {
            // Load the key pair from the Android Key Store
            entry = keyStore.getEntry(keyAlias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException
                | UnrecoverableEntryException ex) {
            return null;
        }

                /* If the entry is null, keys were never stored under this alias.
         * Debug steps in this situation would be:
         * -Check the list of aliases by iterating over Keystore.aliases(), be sure the alias
         *   exists.
         * -If that's empty, verify they were both stored and pulled from the same keystore
         *   "AndroidKeyStore"
         */
        if (entry == null) {
            return null;
        }
                /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
                 * iteration of your application that was using some other mechanism, or been overwritten
                 * by something else using the same keystore with the same alias.
                 * You can determine the type using entry.getClass() and debug from there.
                 */
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            return null;
        }

        return entry;
    }
}
