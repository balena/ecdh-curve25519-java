package com.twigo.app.purchase.djb;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.twigo.app.purchase.djb.Curve25519.KEY_SIZE;

public class Curve25519KeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private SecureRandom mSecureRandom;

    @Override
    public void initialize(int keySize, SecureRandom secureRandom) {
        if (keySize != KEY_SIZE)
            throw new InvalidParameterException("Unknown key type");
        mSecureRandom = secureRandom;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof Curve25519ParameterSpec))
            throw new InvalidAlgorithmParameterException("parameter object not a Curve25519ParameterSpec");
        mSecureRandom = secureRandom;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (mSecureRandom == null) {
            throw new IllegalStateException(Curve25519Provider.ALGORITHM
                    + " not initialised.");
        }

        byte[] privateKey = new byte[KEY_SIZE];
        mSecureRandom.nextBytes(privateKey);

        byte[] publicKey = new byte[KEY_SIZE];
        byte[] s = new byte[KEY_SIZE];
        Curve25519.keygen(publicKey, s, privateKey);

        return new KeyPair(new Curve25519PublicKey(publicKey),
                new Curve25519PrivateKey(privateKey));
    }
}
