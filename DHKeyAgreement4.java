
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
   /*
    * This program executes the Diffie-Hellman key agreement protocol between
    * 3 parties: Alice, Bob, and Carol using a shared 2048-bit DH parameter.
    */
    public class DHKeyAgreement4 {
        private DHKeyAgreement4() {}
        public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with 2048-bit key size
            System.out.println("ALICE: Generate DH keypair ...");
            KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
            aliceKpairGen.initialize(2048);
            KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
			
			
        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
            DHParameterSpec dhParamShared = ((DHPublicKey)aliceKpair.getPublic()).getParams();
			
			
        // Bob creates his own DH key pair using the same params
            System.out.println("BOB: Generate DH keypair ...");
            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamShared);
            KeyPair bobKpair = bobKpairGen.generateKeyPair();
        // Carol creates her own DH key pair using the same params
            System.out.println("CAROL: Generate DH keypair ...");
            KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
            carolKpairGen.initialize(dhParamShared);
            KeyPair carolKpair = carolKpairGen.generateKeyPair();
		// Dan creates his own DH key pair using the same params
			System.out.println("DAN: Generate DH keypair ...");
            KeyPairGenerator danKpairGen = KeyPairGenerator.getInstance("DH");
            danKpairGen.initialize(dhParamShared);
            KeyPair danKpair = danKpairGen.generateKeyPair();
			
			
        // Alice initialize
            System.out.println("ALICE: Initialize ...");
            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
            aliceKeyAgree.init(aliceKpair.getPrivate());
        // Bob initialize
            System.out.println("BOB: Initialize ...");
            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKpair.getPrivate());
        // Carol initialize
            System.out.println("CAROL: Initialize ...");
            KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
            carolKeyAgree.init(carolKpair.getPrivate());
		// Dan initialize
			System.out.println("Dan: Initialize ...");
            KeyAgreement danKeyAgree = KeyAgreement.getInstance("DH");
            danKeyAgree.init(danKpair.getPrivate());
			
			
        // Alice uses Dan's public key
            Key ad = aliceKeyAgree.doPhase(danKpair.getPublic(), false);
        // Bob uses Alice's public key
            Key ba = bobKeyAgree.doPhase(aliceKpair.getPublic(), false);
        // Carol uses Bob's public key
            Key cb = carolKeyAgree.doPhase(bobKpair.getPublic(), false);
		// Dan uses Carol's public key
			Key dc = danKeyAgree.doPhase(carolKpair.getPublic(), false);

			
        // Alice attach's her key to Dan's key from above
            Key adc = aliceKeyAgree.doPhase(dc, false);
        // Bob attach's his key to Alice's key from above
            Key bad = bobKeyAgree.doPhase(ad, false);
        // Carol attach's her key to Bob's key from above
            Key cba = carolKeyAgree.doPhase(ba, false);
		// Dan attach's his key to Carol's key from above
			Key dcb = danKeyAgree.doPhase(cb, false);

			
		// Alice uses Carol's result from above
			aliceKeyAgree.doPhase(dcb, true);
		// Bob uses Dan's result from above
			bobKeyAgree.doPhase(adc, true);
		// Carol uses Alice's result from above
			carolKeyAgree.doPhase(bad, true);
		// Dan uses Bob's result from above
			danKeyAgree.doPhase(cba, true);
			
		/*
		   Everyone now owns a single key encompassing all 
		   their neighbors keys 
		*/	
			
        // Alice, Bob, Carol & Dan compute their secrets
            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
            byte[] bobSharedSecret = bobKeyAgree.generateSecret();
            System.out.println("Bob secret: " + toHexString(bobSharedSecret));
            byte[] carolSharedSecret = carolKeyAgree.generateSecret();
            System.out.println("Carol secret: " + toHexString(carolSharedSecret));
			byte[] danSharedSecret = danKeyAgree.generateSecret();
            System.out.println("Dan secret: " + toHexString(danSharedSecret));
			
			
        // Compare Alice and Dan
            if (!java.util.Arrays.equals(aliceSharedSecret, danSharedSecret))
                throw new Exception("Alice and Dan differ");
            System.out.println("Alice and Dan are the same");
        // Compare Bob and Alice
            if (!java.util.Arrays.equals(bobSharedSecret, aliceSharedSecret))
                throw new Exception("Bob and Alice differ");
            System.out.println("Bob and Alice are the same");
		// Compare Carol and Bob
			if (!java.util.Arrays.equals(carolSharedSecret, bobSharedSecret))
                throw new Exception("Carol and Bob differ");
            System.out.println("Carol and Bob are the same");
        }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
        private static void byte2hex(byte b, StringBuffer buf) {
            char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            int high = ((b & 0xf0) >> 4);
            int low = (b & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }
    /*
     * Converts a byte array to hex string
     */
        private static String toHexString(byte[] block) {
            StringBuffer buf = new StringBuffer();
            int len = block.length;
            for (int i = 0; i < len; i++) {
                byte2hex(block[i], buf);
                if (i < len-1) {
                    buf.append(":");
                }
            }
            return buf.toString();
        }
    }