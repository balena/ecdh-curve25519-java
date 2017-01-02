package org.balena.security.ecdh.curve25519;

import android.support.annotation.NonNull;

import javax.crypto.SecretKey;

public class Curve25519SecretKey extends Curve25519Key implements SecretKey {
    public Curve25519SecretKey(@NonNull byte[] key) {
        super(key);
    }
}
