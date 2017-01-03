package br.eti.balena.security.ecdh.curve25519.spi;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;

public class Curve25519Provider extends Provider {
    public Curve25519Provider() {
        super("Curve25519", 1.0, "Curve25519 provider v1.0, implementing " +
                "DJB Curve25519 key pair generation and agreement.");

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                setup();
                return null;
            }
        });
    }

    protected void setup() {
        // see https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html
        put("Curve25519KeyPairGenerator." + ALGORITHM,
                Curve25519KeyPairGeneratorSpi.class.getCanonicalName());
        put("Curve25519KeyAgreement." + ALGORITHM,
                Curve25519KeyAgreementSpi.class.getCanonicalName());
    }
}
