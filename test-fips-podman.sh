#!/bin/bash

# FIPS Testing Script for GeoServer using Podman
# This script tests the FIPS functionality in a containerized environment

set -e

echo "=== GeoServer FIPS Testing Script (Podman) ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "SUCCESS" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" = "WARNING" ]; then
        echo -e "${YELLOW}⚠${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

# Check if Podman is available
if ! command -v podman > /dev/null 2>&1; then
    print_status "ERROR" "Podman is not installed. Please install Podman and try again."
    exit 1
fi

print_status "SUCCESS" "Podman is available ($(podman --version))"

# Build the FIPS-enabled image
echo
echo "Building FIPS-enabled GeoServer image..."
podman build -f Dockerfile.fips -t geoserver-fips:latest .

if [ $? -eq 0 ]; then
    print_status "SUCCESS" "FIPS-enabled GeoServer image built successfully"
else
    print_status "ERROR" "Failed to build FIPS-enabled GeoServer image"
    exit 1
fi

# Start the container using podman-compose or direct podman
echo
echo "Starting FIPS-enabled GeoServer container..."

# Check if podman-compose is available
if command -v podman-compose > /dev/null 2>&1; then
    print_status "SUCCESS" "Using podman-compose"
    podman-compose -f docker-compose.fips.yml up -d geoserver-fips
else
    print_status "WARNING" "podman-compose not found, using direct podman commands"
    # Stop and remove existing container if it exists
    podman stop geoserver-fips 2>/dev/null || true
    podman rm geoserver-fips 2>/dev/null || true
    
    # Start container directly
    podman run -d \
        --name geoserver-fips \
        -p 8080:8080 \
        -e GEOSERVER_KEYSTORE_TYPE=BCFKS \
        -e GEOSERVER_KEYSTORE_PASSWORD=geoserver \
        -e GEOSERVER_KEYSTORE_FILE=keystore.bcfks \
        -e GEOSERVER_KEYSTORE_PROVIDER=BC \
        -e GEOSERVER_MASTER_PASSWORD=geoserver \
        geoserver-fips:latest
fi

# Wait for GeoServer to start
echo
echo "Waiting for GeoServer to start..."
sleep 30

# Check if GeoServer is responding
echo
echo "Testing GeoServer connectivity..."
if curl -f http://localhost:8080/geoserver/web/ > /dev/null 2>&1; then
    print_status "SUCCESS" "GeoServer is responding on port 8080"
else
    print_status "WARNING" "GeoServer is not responding yet, checking logs..."
    podman logs geoserver-fips
fi

# Check FIPS mode in container
echo
echo "Checking FIPS mode in container..."
FIPS_CHECK=$(podman exec geoserver-fips java -Dcom.redhat.fips=true -cp /opt/geoserver/webapps/geoserver/WEB-INF/lib/* org.geoserver.security.FIPSKeyStoreProvider 2>/dev/null || echo "FIPS_CHECK_FAILED")

if echo "$FIPS_CHECK" | grep -q "FIPS mode detected"; then
    print_status "SUCCESS" "FIPS mode is active in the container"
else
    print_status "WARNING" "FIPS mode check failed or not detected"
fi

# Check keystore type
echo
echo "Checking keystore configuration..."
KEYSTORE_TYPE=$(podman exec geoserver-fips bash -c 'echo $GEOSERVER_KEYSTORE_TYPE')
if [ "$KEYSTORE_TYPE" = "BCFKS" ]; then
    print_status "SUCCESS" "Keystore type is set to BCFKS (FIPS-compliant)"
else
    print_status "WARNING" "Keystore type is $KEYSTORE_TYPE (not BCFKS)"
fi

# Test keystore creation
echo
echo "Testing keystore creation..."
podman exec geoserver-fips bash -c '
cd /opt/geoserver
java -Dcom.redhat.fips=true -cp webapps/geoserver/WEB-INF/lib/* org.geoserver.security.MigrateKeystore \
    --source-type PKCS12 \
    --source-file /tmp/test-keystore.p12 \
    --source-password testpass \
    --target-type PKCS12 \
    --target-file /tmp/test-keystore-new.p12 \
    --target-password testpass \
    --create-new
'

if [ $? -eq 0 ]; then
    print_status "SUCCESS" "Keystore creation test passed"
else
    print_status "WARNING" "Keystore creation test failed"
fi

# Check container logs for any FIPS-related messages
echo
echo "Checking container logs for FIPS-related messages..."
FIPS_LOGS=$(podman logs geoserver-fips 2>&1 | grep -i fips || echo "No FIPS logs found")

if echo "$FIPS_LOGS" | grep -q "FIPS"; then
    print_status "SUCCESS" "FIPS-related messages found in logs"
    echo "$FIPS_LOGS"
else
    print_status "WARNING" "No FIPS-related messages found in logs"
fi

# Test security endpoints
echo
echo "Testing security endpoints..."
if curl -f http://localhost:8080/geoserver/rest/security/ > /dev/null 2>&1; then
    print_status "SUCCESS" "Security REST endpoint is accessible"
else
    print_status "WARNING" "Security REST endpoint is not accessible"
fi

echo
echo "=== FIPS Testing Complete ==="
echo
echo "To access GeoServer: http://localhost:8080/geoserver"
echo "Default credentials: admin/geoserver"
echo
echo "To stop the container:"
if command -v podman-compose > /dev/null 2>&1; then
    echo "podman-compose -f docker-compose.fips.yml down"
else
    echo "podman stop geoserver-fips && podman rm geoserver-fips"
fi
echo
echo "To view logs:"
echo "podman logs geoserver-fips" 