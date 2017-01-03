# ecdh-curve25519-java

This is a custom Diffie-Hellman key pair generator and a key agreement for the Curve25519 algorithm from Dan Bernstein, implemented as a Java Cryptography Extension (JCE).

The core of the Curve25519 algorithm is a fork of (trevorbernard/curve25519-java)[https://github.com/trevorbernard/curve25519-java.git].

The library contains a `KeyPairGenerator` and a `KeyAgreement` class to get access to the algorithms without registering the JCE provider, as it may require strict JAR signatures and system permissions to do so.


## Gradle depencency

The Gradle dependency is available via (jCenter)[https://bintray.com/guibv/maven/br.eti.balena:ecdh-curve25519].

The minimum API level supported by this library is API 14 (Ice Cream Sandwich).

```gradle
dependencies {
    compile 'br.eti.balena:ecdh-curve25519:0.1.2'
}
```


## Usage

```java
import org.junit.Test;

import java.security.KeyPair;
import javax.crypto.SecretKey;

import br.eti.balena.security.ecdh.curve25519.KeyAgreement;
import br.eti.balena.security.ecdh.curve25519.KeyPairGenerator;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;
import static org.junit.Assert.assertArrayEquals;

public class KeyExchangeTest {
    @Test
    public void keyExchangeTest() throws Exception {
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();

        // Ana generates a key-pair as follows:
        KeyPair anaKeyPair = keyPairGenerator.generateKeyPair();

        // Now Ana saves the privateKey for later, and sends the public key to Bob.
        // The public key bytes are taken as anaKeyPair.getPublic().getEncoded().

        // Bob now generates his key pair:
        KeyPair bobKeyPair = keyPairGenerator.generateKeyPair();

        // Now Bob obtains the bobSharedSecret in this manner:
        KeyAgreement bobKeyAgreement = new KeyAgreement(bobKeyPair.getPrivate());
        bobKeyAgreement.doFinal(anaKeyPair.getPublic());
        SecretKey bobSharedSecret = bobKeyAgreement.generateSecret(ALGORITHM);

        // And, by using this shared secret, Bob can now encrypt the message.

        // At the Ana's side, the same shared secret is generated from the
        // public key sent by Bob.
        KeyAgreement anaKeyAgreement = new KeyAgreement(anaKeyPair.getPrivate());
        anaKeyAgreement.doFinal(bobKeyPair.getPublic());
        SecretKey anaSharedSecret = anaKeyAgreement.generateSecret(ALGORITHM);

        // Confirms that both shared secrets are equal.
        assertArrayEquals(anaSharedSecret.getEncoded(), bobSharedSecret.getEncoded());
    }
}
```

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
