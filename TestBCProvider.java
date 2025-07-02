import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestBCProvider {
    public static void main(String[] args) {
        try {
            // Register BouncyCastle provider
            Security.addProvider(new BouncyCastleProvider());
            
            // Check if provider is registered
            System.out.println("BC Provider registered: " + Security.getProvider("BC"));
            
            // Test BCFKS keystore
            java.security.KeyStore keystore = java.security.KeyStore.getInstance("BCFKS", "BC");
            keystore.load(null, "testpass".toCharArray());
            System.out.println("✓ BCFKS keystore created successfully");
            
        } catch (Exception e) {
            System.err.println("✗ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 