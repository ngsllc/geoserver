
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.Security;

public class SealingTest {
    public static void main(String[] args) {
        try {
            System.out.println("Loading BC...");
            Security.addProvider(new BouncyCastleProvider());
            System.out.println("BC Loaded.");
        } catch (Throwable t) {
            System.out.println("BC Failed: " + t.getMessage());
        }

        try {
            System.out.println("Loading BC-FIPS...");
            Security.addProvider(new BouncyCastleFipsProvider());
            System.out.println("BC-FIPS Loaded.");
        } catch (Throwable t) {
            System.out.println("BC-FIPS Failed: " + t.getMessage());
        }
    }
}
