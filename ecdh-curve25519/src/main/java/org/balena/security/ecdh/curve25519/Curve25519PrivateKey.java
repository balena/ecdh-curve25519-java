package com.twigo.app.purchase.djb;

import java.security.PrivateKey;

public class Curve25519PrivateKey implements PrivateKey {
    private byte[] mKey;

    public Curve25519PrivateKey(byte[] key) {
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
