package br.eti.balena.security.ecdh.curve25519.spi;

import br.eti.balena.security.ecdh.curve25519.Curve25519KeyPairGenerator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;
import static br.eti.balena.security.ecdh.curve25519.Curve25519.KEY_SIZE;

public class Curve25519KeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private Curve25519KeyPairGenerator mImplementation;

    @Override
    public void initialize(int keySize, SecureRandom secureRandom) {
        if (keySize != KEY_SIZE)
            throw new InvalidParameterException("Unknown key type");
        mImplementation = new Curve25519KeyPairGenerator(secureRandom);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof Curve25519ParameterSpec))
            throw new InvalidAlgorithmParameterException("parameter object not a Curve25519ParameterSpec");
        mImplementation = new Curve25519KeyPairGenerator(secureRandom);
    }

    @Override
    public KeyPair generateKeyPair() {
        if (mImplementation == null) {
            throw new IllegalStateException(ALGORITHM
                    + " not initialised.");
        }
        return mImplementation.generateKeyPair();
    }
}
