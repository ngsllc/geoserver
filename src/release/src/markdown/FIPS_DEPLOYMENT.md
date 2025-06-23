# GeoServer FIPS Deployment Guide

This guide explains how to deploy GeoServer in FIPS (Federal Information Processing Standards) enabled environments using OpenJDK 11 containers.

## Overview

FIPS 140-2 is a U.S. government computer security standard that specifies requirements for cryptographic modules. This implementation provides FIPS-compliant keystore support for GeoServer.

## Prerequisites

- Docker and Docker Compose installed
- FIPS-enabled Linux server (RHEL/CentOS 8+ recommended)
- OpenJDK 11 or later
- At least 4GB RAM available

## Quick Start

### 1. Build and Run with Docker

```bash
# Clone the repository
git clone <repository-url>
cd geoserver

# Build the FIPS-enabled image
docker build -f Dockerfile.fips -t geoserver-fips:latest .

# Start the container
docker-compose -f docker-compose.fips.yml up -d

# Run the test script
./test-fips.sh
```

### 2. Access GeoServer

- **Web Interface**: http://localhost:8080/geoserver
- **Default Credentials**: admin/geoserver
- **REST API**: http://localhost:8080/geoserver/rest/

## FIPS Configuration

### Environment Variables

| Variable | Description | Default | FIPS Recommendation |
|----------|-------------|---------|-------------------|
| `FIPS_MODE` | Enable FIPS mode | false | true |
| `GEOSERVER_KEYSTORE_TYPE` | Keystore type | JCEKS | PKCS12 |
| `JAVA_OPTS` | JVM options | -Xmx2g -Xms1g | Include FIPS flags |

### FIPS Mode Detection

The system automatically detects FIPS mode through:

1. **System Property**: `com.redhat.fips=true`
2. **Environment Variable**: `FIPS_MODE=true`
3. **Provider Availability**: FIPS-compliant BouncyCastle provider

### Supported Keystore Types in FIPS Mode

| Keystore Type | FIPS Compliant | Notes |
|---------------|----------------|-------|
| PKCS12 | ✅ Yes | Recommended for FIPS |
| BCFKS | ✅ Yes | BouncyCastle FIPS Keystore |
| JCEKS | ❌ No | Not FIPS compliant |
| JKS | ❌ No | Not FIPS compliant |

## Deployment Options

### Option 1: Docker Container (Recommended)

```bash
# Production deployment
docker run -d \
  --name geoserver-fips \
  -p 8080:8080 \
  -e FIPS_MODE=true \
  -e GEOSERVER_KEYSTORE_TYPE=PKCS12 \
  -e JAVA_OPTS="-Dcom.redhat.fips=true -Xmx4g -Xms2g" \
  -v /path/to/data:/opt/geoserver/data_dir \
  -v /path/to/logs:/opt/geoserver/logs \
  geoserver-fips:latest
```

### Option 2: Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: geoserver-fips
spec:
  replicas: 1
  selector:
    matchLabels:
      app: geoserver-fips
  template:
    metadata:
      labels:
        app: geoserver-fips
    spec:
      containers:
      - name: geoserver
        image: geoserver-fips:latest
        ports:
        - containerPort: 8080
        env:
        - name: FIPS_MODE
          value: "true"
        - name: GEOSERVER_KEYSTORE_TYPE
          value: "PKCS12"
        - name: JAVA_OPTS
          value: "-Dcom.redhat.fips=true -Xmx4g -Xms2g"
        volumeMounts:
        - name: data-volume
          mountPath: /opt/geoserver/data_dir
        - name: logs-volume
          mountPath: /opt/geoserver/logs
      volumes:
      - name: data-volume
        persistentVolumeClaim:
          claimName: geoserver-data-pvc
      - name: logs-volume
        persistentVolumeClaim:
          claimName: geoserver-logs-pvc
```

### Option 3: Bare Metal Installation

1. **Install OpenJDK 11**:
   ```bash
   sudo yum install java-11-openjdk-devel
   ```

2. **Set FIPS environment**:
   ```bash
   export FIPS_MODE=true
   export GEOSERVER_KEYSTORE_TYPE=PKCS12
   export JAVA_OPTS="-Dcom.redhat.fips=true -Xmx4g -Xms2g"
   ```

3. **Download and run GeoServer**:
   ```bash
   wget https://build.geoserver.org/geoserver/2.28-SNAPSHOT/geoserver-2.28-SNAPSHOT-bin.zip
   unzip geoserver-2.28-SNAPSHOT-bin.zip
   cd geoserver-2.28-SNAPSHOT
   java $JAVA_OPTS -jar start.jar
   ```

## Keystore Migration

### Migrating Existing Keystores to FIPS

```bash
# Using the migration tool
java -cp geoserver.jar org.geoserver.security.MigrateKeystore \
  --source-type JCEKS \
  --source-file /path/to/old/keystore.jceks \
  --source-password oldpassword \
  --target-type PKCS12 \
  --target-file /path/to/new/keystore.p12 \
  --target-password newpassword
```

### Creating New FIPS-Compliant Keystores

```bash
# Create new PKCS12 keystore
keytool -genkeypair \
  -alias geoserver \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -storepass password \
  -validity 3650
```

## Security Considerations

### FIPS Compliance Checklist

- [ ] Use FIPS-compliant keystore types (PKCS12, BCFKS)
- [ ] Enable FIPS mode via system properties
- [ ] Use approved cryptographic algorithms
- [ ] Validate keystore integrity
- [ ] Implement proper key management
- [ ] Monitor security logs

### Recommended Security Settings

```properties
# java.security properties for FIPS compliance
security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.3=SunEC
security.provider.4=SunJSSE
security.provider.5=SunJCE
security.provider.6=SunJGSS
security.provider.7=SunSASL
security.provider.8=XMLDSig
security.provider.9=SunPCSC
security.provider.10=JdkLDAP
security.provider.11=JdkSASL
security.provider.12=SunPKCS11
```

## Monitoring and Troubleshooting

### Health Checks

```bash
# Check if GeoServer is running
curl -f http://localhost:8080/geoserver/web/

# Check FIPS mode
docker exec geoserver-fips java -Dcom.redhat.fips=true -version

# Check keystore configuration
docker exec geoserver-fips echo $GEOSERVER_KEYSTORE_TYPE
```

### Common Issues

1. **FIPS Provider Not Found**:
   - Ensure FIPS-compliant BouncyCastle is available
   - Check system property `com.redhat.fips=true`

2. **Keystore Loading Errors**:
   - Verify keystore type is FIPS-compliant
   - Check keystore password and integrity

3. **Performance Issues**:
   - FIPS mode may have performance impact
   - Consider increasing JVM heap size

### Log Analysis

```bash
# View GeoServer logs
docker logs geoserver-fips

# Search for FIPS-related messages
docker logs geoserver-fips | grep -i fips

# Check security-related logs
docker logs geoserver-fips | grep -i security
```

## Testing

### Automated Testing

Run the provided test script:

```bash
./test-fips.sh
```

This script will:
- Build the FIPS-enabled image
- Start the container
- Verify FIPS mode is active
- Test keystore functionality
- Check security endpoints

### Manual Testing

1. **FIPS Mode Verification**:
   ```bash
   docker exec geoserver-fips java -Dcom.redhat.fips=true -cp /opt/geoserver/webapps/geoserver/WEB-INF/lib/* org.geoserver.security.FIPSKeyStoreProvider
   ```

2. **Keystore Creation Test**:
   ```bash
   docker exec geoserver-fips java -cp /opt/geoserver/webapps/geoserver/WEB-INF/lib/* org.geoserver.security.MigrateKeystore --help
   ```

3. **Security Endpoint Test**:
   ```bash
   curl -u admin:geoserver http://localhost:8080/geoserver/rest/security/
   ```

## Performance Tuning

### JVM Settings for FIPS

```bash
# Recommended JVM options for FIPS environments
JAVA_OPTS="-Dcom.redhat.fips=true \
  -Xmx4g \
  -Xms2g \
  -XX:+UseG1GC \
  -XX:MaxGCPauseMillis=200 \
  -XX:+UnlockExperimentalVMOptions \
  -XX:+UseCGroupMemoryLimitForHeap"
```

### Container Resource Limits

```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "500m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

## Support

For issues related to FIPS deployment:

1. Check the [GeoServer Security Documentation](https://docs.geoserver.org/stable/en/user/security/)
2. Review the [FIPS Configuration Guide](KEYSTORE_CONFIGURATION.md)
3. Consult the [Running GeoServer Guide](RUNNING.md)

## References

- [FIPS 140-2 Standard](https://csrc.nist.gov/publications/detail/fips/140/2/final)
- [BouncyCastle FIPS Documentation](https://www.bouncycastle.org/fips-java/)
- [OpenJDK Security Guide](https://docs.oracle.com/en/java/javase/11/security/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/) 