package org.balena.security.ecdh.curve25519.spi;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class Curve25519Provider extends Provider {
    public static final String ALGORITHM = "curve25519";

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
        put("KeyPairGenerator." + ALGORITHM,
                Curve25519KeyPairGeneratorSpi.class.getCanonicalName());
        put("KeyAgreement." + ALGORITHM,
                Curve25519KeyAgreementSpi.class.getCanonicalName());
    }
}
