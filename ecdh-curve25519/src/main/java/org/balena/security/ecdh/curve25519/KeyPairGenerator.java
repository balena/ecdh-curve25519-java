package org.balena.security.ecdh.curve25519;

import android.support.annotation.NonNull;

import java.security.KeyPair;
import java.security.SecureRandom;

import static org.balena.security.ecdh.curve25519.Curve25519.KEY_SIZE;

public class KeyPairGenerator {
    private SecureRandom mSecureRandom;

    public KeyPairGenerator() {
        this(new SecureRandom());
    }

    public KeyPairGenerator(@NonNull SecureRandom secureRandom) {
        mSecureRandom = secureRandom;
    }

    public KeyPair generateKeyPair() {
        byte[] privateKey = new byte[KEY_SIZE];
        mSecureRandom.nextBytes(privateKey);

        byte[] publicKey = new byte[KEY_SIZE];
        byte[] s = new byte[KEY_SIZE];
        Curve25519.keygen(publicKey, s, privateKey);

        return new KeyPair(new Curve25519PublicKey(publicKey),
                new Curve25519PrivateKey(privateKey));
    }
}
