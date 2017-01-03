package br.eti.balena.security.ecdh.curve25519.spi;

import br.eti.balena.security.ecdh.curve25519.Curve25519KeyAgreement;
import br.eti.balena.security.ecdh.curve25519.Curve25519PrivateKey;
import br.eti.balena.security.ecdh.curve25519.Curve25519PublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;

public class Curve25519KeyAgreementSpi extends KeyAgreementSpi {
    private Curve25519KeyAgreement mImplementation;

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
            mImplementation = new Curve25519KeyAgreement((PrivateKey)key);
        } else {
            throw new InvalidKeyException();
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (mImplementation == null) {
            throw new IllegalStateException(ALGORITHM
                    + " not initialised.");
        }
        if (!lastPhase) {
            throw new IllegalStateException(ALGORITHM
                    + " can only be between two parties.");
        }
        if (!(key instanceof Curve25519PublicKey)) {
            throw new InvalidKeyException(ALGORITHM
                    + " key agreement requires "
                    + Curve25519PublicKey.class.getSimpleName() + " for doPhase");
        }
        mImplementation.doFinal((PublicKey)key);
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (mImplementation == null) {
            throw new IllegalStateException(ALGORITHM
                    + " not initialised.");
        }
        return mImplementation.generateSecret();
    }

    @Override
    protected int engineGenerateSecret(byte[] bytes, int i)
            throws IllegalStateException, ShortBufferException {
        if (mImplementation == null) {
            throw new IllegalStateException(ALGORITHM
                    + " not initialised.");
        }
        return mImplementation.generateSecret(bytes, i);
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (mImplementation == null) {
            throw new IllegalStateException(ALGORITHM
                    + " not initialised.");
        }
        return mImplementation.generateSecret(algorithm);
    }
}
