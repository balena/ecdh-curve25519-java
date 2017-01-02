package com.twigo.app.purchase.djb;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import static com.twigo.app.purchase.djb.Curve25519.KEY_SIZE;

public class Curve25519KeyAgreementSpi extends KeyAgreementSpi {
    private byte[] mPrivateKey;
    private byte[] mSharedSecret;

    @Override
    protected void engineInit(Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            engineInit(key, new Curve25519ParameterSpec(), secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec,
            SecureRandom secureRandom)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof Curve25519ParameterSpec))
            throw new InvalidAlgorithmParameterException("Unknown parameter spec");
        if (key instanceof Curve25519PrivateKey) {
            mPrivateKey = key.getEncoded();
        } else {
            throw new InvalidKeyException();
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (mPrivateKey == null) {
            throw new IllegalStateException(Curve25519Provider.ALGORITHM
                    + " not initialised.");
        }
        if (!lastPhase) {
            throw new IllegalStateException(Curve25519Provider.ALGORITHM
                    + " can only be between two parties.");
        }
        if (!(key instanceof Curve25519PublicKey)) {
            throw new InvalidKeyException(Curve25519Provider.ALGORITHM
                    + " key agreement requires "
                    + Curve25519PublicKey.class.getSimpleName() + " for doPhase");
        }
        mSharedSecret = new byte[KEY_SIZE];
        Curve25519.curve(mSharedSecret, mPrivateKey, key.getEncoded());
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        byte[] sharedSecret = new byte[KEY_SIZE];
        try {
            engineGenerateSecret(sharedSecret, 0);
        } catch (ShortBufferException e) {
            e.printStackTrace();
        }
        return sharedSecret;
    }

    @Override
    protected int engineGenerateSecret(byte[] bytes, int i)
            throws IllegalStateException, ShortBufferException {
        if (bytes.length - i < KEY_SIZE)
            throw new ShortBufferException();
        System.arraycopy(mSharedSecret, 0, bytes, i, KEY_SIZE);
        return KEY_SIZE;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (!algorithm.equals(Curve25519Provider.ALGORITHM))
            throw new NoSuchAlgorithmException("Unknown algorithm encountered: " + algorithm);
        return new Curve25519SecretKey(engineGenerateSecret());
    }
}
