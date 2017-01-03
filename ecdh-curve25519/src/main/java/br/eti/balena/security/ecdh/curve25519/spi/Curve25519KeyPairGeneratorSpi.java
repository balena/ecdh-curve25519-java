package br.eti.balena.security.ecdh.curve25519.spi;

import br.eti.balena.security.ecdh.curve25519.Curve25519;
import br.eti.balena.security.ecdh.curve25519.spec.Curve25519ParameterSpec;
import br.eti.balena.security.ecdh.curve25519.Curve25519PrivateKey;
import br.eti.balena.security.ecdh.curve25519.Curve25519PublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;
import static br.eti.balena.security.ecdh.curve25519.Curve25519.KEY_SIZE;

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
            throw new IllegalStateException(ALGORITHM
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
