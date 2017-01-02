package org.balena.security.ecdh.curve25519;

import android.support.annotation.NonNull;

import org.balena.security.ecdh.curve25519.spi.Curve25519Provider;

import java.security.Key;

class Curve25519Key implements Key {
    private byte[] mKey;

    Curve25519Key(@NonNull byte[] key) {
        mKey = key;
    }

    @Override
    public String getAlgorithm() {
        return Curve25519Provider.ALGORITHM;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return mKey;
    }
}
