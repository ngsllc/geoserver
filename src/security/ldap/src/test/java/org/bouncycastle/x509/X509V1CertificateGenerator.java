package org.bouncycastle.x509;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
// import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509V1CertificateGenerator {
    static {
        if (Security.getProvider("BCFIPS") == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    private BigInteger serialNumber;
    private X500Name issuerDN;
    private Date notBefore;
    private Date notAfter;
    private X500Name subjectDN;
    private PublicKey publicKey;
    private String signatureAlgorithm;

    public X509V1CertificateGenerator() {}

    public void reset() {
        serialNumber = null;
        issuerDN = null;
        notBefore = null;
        notAfter = null;
        subjectDN = null;
        publicKey = null;
        signatureAlgorithm = null;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    /*
    public void setIssuerDN(X509Name issuerDN) {
        this.issuerDN = X500Name.getInstance(issuerDN.toASN1Primitive());
    }
    */

    public void setIssuerDN(javax.security.auth.x500.X500Principal issuer) {
        try {
            this.issuerDN = X500Name.getInstance(issuer.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Can't process X500Principal", e);
        }
    }

    public void setNotBefore(Date date) {
        this.notBefore = date;
    }

    public void setNotAfter(Date date) {
        this.notAfter = date;
    }

    /*
    public void setSubjectDN(X509Name subjectDN) {
        this.subjectDN = X500Name.getInstance(subjectDN.toASN1Primitive());
    }
    */

    public void setSubjectDN(javax.security.auth.x500.X500Principal subject) {
        try {
            this.subjectDN = X500Name.getInstance(subject.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Can't process X500Principal", e);
        }
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public X509Certificate generate(PrivateKey key)
            throws CertificateEncodingException, IllegalStateException, NoSuchProviderException,
                    NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return generate(key, "BCFIPS");
    }

    public X509Certificate generate(PrivateKey key, String provider)
            throws CertificateEncodingException, IllegalStateException, NoSuchProviderException,
                    NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        try {
            // Force BCFIPS provider if BC is requested, as we are running with bc-fips
            if ("BC".equals(provider)) {
                provider = "BCFIPS";
            }
            JcaX509v1CertificateBuilder builder =
                    new JcaX509v1CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN, publicKey);

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(provider)
                    .build(key);

            return new JcaX509CertificateConverter().setProvider(provider).getCertificate(builder.build(signer));

        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate certificate", e);
        }
    }
}
