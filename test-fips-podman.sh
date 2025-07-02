#!/bin/bash

# FIPS Testing Script for GeoServer using Podman
# This script tests the FIPS functionality in a containerized environment

set -e

# Function to find an available port
find_available_port() {
    local start_port=${1:-8080}
    local port=$start_port
    
    while [ $port -lt 65535 ]; do
        if ! netstat -tln | grep -q ":$port "; then
            echo $port
            return 0
        fi
        port=$((port + 1))
    done
    
    echo "No available ports found in range $start_port-65534" >&2
    return 1
}

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

# Function to show usage
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

FIPS Testing Script for GeoServer using Podman

OPTIONS:
    -h, --help          Show this help message
    -c, --clean         Clean up existing containers and images before starting
    -p, --port PORT     Use custom port (default: 8080)
    -s, --skip-build    Skip building GeoServer WAR file (use existing)
    -d, --skip-download Skip downloading Jetty (use existing)

EXAMPLES:
    $0                    # Run with default settings
    $0 --clean           # Clean up and run
    $0 --port 8081       # Use port 8081 instead of 8080
    $0 --skip-build      # Skip building GeoServer (faster if already built)

PREREQUISITES:
    - Podman installed and running
    - Maven (mvn) available in PATH
    - wget available in PATH
    - curl available in PATH
    - Sufficient disk space for GeoServer build (~2GB)
    - Sufficient memory for Maven build (~2GB RAM)

EOF
}

# Parse command line arguments
CLEAN_MODE=false
CUSTOM_PORT=8080
SKIP_BUILD=false
SKIP_DOWNLOAD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--clean)
            CLEAN_MODE=true
            shift
            ;;
        -p|--port)
            CUSTOM_PORT="$2"
            shift 2
            ;;
        -s|--skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -d|--skip-download)
            SKIP_DOWNLOAD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Find available port if the specified port is in use
REQUESTED_PORT=$CUSTOM_PORT
CUSTOM_PORT=$(find_available_port $CUSTOM_PORT)
if [ $? -ne 0 ]; then
    print_status "ERROR" "Failed to find available port starting from $REQUESTED_PORT"
    exit 1
fi

if [ "$REQUESTED_PORT" != "$CUSTOM_PORT" ]; then
    print_status "WARNING" "Port $REQUESTED_PORT is in use, using port $CUSTOM_PORT instead"
fi

echo "=== GeoServer FIPS Testing Script (Podman) ==="
echo "Port: $CUSTOM_PORT"
echo "Clean mode: $CLEAN_MODE"
echo "Skip build: $SKIP_BUILD"
echo "Skip download: $SKIP_DOWNLOAD"
echo

# Function to cleanup on exit
cleanup() {
    echo
    echo "Cleaning up..."
    # Remove temporary files if they exist
    rm -f jetty-distribution-9.4.44.v20210927.tar.gz
    print_status "SUCCESS" "Cleanup completed"
}

# Function to cleanup existing containers and images
cleanup_existing() {
    if [ "$CLEAN_MODE" = true ]; then
        echo "Cleaning up existing containers and images..."
        
        # Stop and remove existing containers
        podman stop geoserver-fips 2>/dev/null || true
        podman rm geoserver-fips 2>/dev/null || true
        
        # Remove existing images
        podman rmi geoserver-fips:latest 2>/dev/null || true
        
        print_status "SUCCESS" "Existing containers and images cleaned up"
    fi
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Function to check prerequisites
check_prerequisites() {
    local missing_deps=()
    
    # Check for wget
    if ! command -v wget > /dev/null 2>&1; then
        missing_deps+=("wget")
    fi
    
    # Check for mvn (Maven)
    if ! command -v mvn > /dev/null 2>&1; then
        missing_deps+=("maven")
    fi
    
    # Check for curl
    if ! command -v curl > /dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "ERROR" "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install the missing dependencies and try again."
        exit 1
    fi
}

# Check if Podman is available
if ! command -v podman > /dev/null 2>&1; then
    print_status "ERROR" "Podman is not installed. Please install Podman and try again."
    exit 1
fi

print_status "SUCCESS" "Podman is available ($(podman --version))"

# Check prerequisites
check_prerequisites

# Cleanup existing containers and images if requested
cleanup_existing

# Function to download Jetty distribution
download_jetty() {
    if [ "$SKIP_DOWNLOAD" = true ]; then
        print_status "WARNING" "Skipping Jetty download (--skip-download specified)"
        return 0
    fi
    
    local jetty_file="jetty-distribution-9.4.44.v20210927.tar.gz"
    local jetty_url="https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/9.4.44.v20210927/jetty-distribution-9.4.44.v20210927.tar.gz"
    
    if [ ! -f "$jetty_file" ]; then
        echo "Downloading Jetty distribution..."
        local retry_count=0
        local max_retries=3
        
        while [ $retry_count -lt $max_retries ]; do
            if wget -q --timeout=30 "$jetty_url" -O "$jetty_file"; then
                print_status "SUCCESS" "Jetty distribution downloaded successfully"
                return 0
            else
                retry_count=$((retry_count + 1))
                if [ $retry_count -lt $max_retries ]; then
                    print_status "WARNING" "Download failed, retrying... (attempt $retry_count/$max_retries)"
                    sleep 2
                else
                    print_status "ERROR" "Failed to download Jetty distribution after $max_retries attempts"
                    return 1
                fi
            fi
        done
    else
        print_status "SUCCESS" "Jetty distribution already exists"
    fi
}

# Function to build GeoServer WAR file
build_geoserver() {
    if [ "$SKIP_BUILD" = true ]; then
        print_status "WARNING" "Skipping GeoServer build (--skip-build specified)"
        return 0
    fi
    
    local war_file="src/web/app/target/geoserver.war"
    
    if [ ! -f "$war_file" ]; then
        echo "Building GeoServer WAR file..."
        if [ -d "src" ]; then
            cd src
            echo "Running Maven build (this may take several minutes)..."
            if mvn clean package -DskipTests -q; then
                print_status "SUCCESS" "GeoServer WAR file built successfully"
                cd ..
            else
                print_status "ERROR" "Failed to build GeoServer WAR file"
                echo "Maven build failed. Please check the error messages above."
                echo "Common issues:"
                echo "  - Insufficient memory (try: export MAVEN_OPTS='-Xmx2g')"
                echo "  - Network connectivity issues"
                echo "  - Missing Java dependencies"
                cd ..
                exit 1
            fi
        else
            print_status "ERROR" "src directory not found. Please run this script from the GeoServer root directory."
            exit 1
        fi
    else
        print_status "SUCCESS" "GeoServer WAR file already exists"
    fi
}

# Check and download/build dependencies
echo
echo "Checking and preparing dependencies..."

# Download Jetty distribution
download_jetty

# Build GeoServer WAR file
build_geoserver

# Build FIPS utilities JAR
build_fips_utils() {
    local utils_jar="fips-utils.jar"
    
    if [ ! -f "$utils_jar" ]; then
        echo "Building FIPS utilities JAR..."
        if [ -d "src/fips-utils" ]; then
            cd src/fips-utils
            echo "Building FIPS utilities..."
            if mvn clean package -q; then
                cd ../..
                # Copy the built JAR to the root directory
                cp src/fips-utils/target/geoserver-fips-utils-2.27.1.jar fips-utils.jar
                print_status "SUCCESS" "FIPS utilities JAR built successfully"
            else
                print_status "ERROR" "Failed to build FIPS utilities JAR"
                cd ../..
                exit 1
            fi
        else
            print_status "ERROR" "src/fips-utils directory not found"
            exit 1
        fi
    else
        print_status "SUCCESS" "FIPS utilities JAR already exists"
    fi
}

# Build FIPS utilities JAR
build_fips_utils

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
        -p $CUSTOM_PORT:8080 \
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
if curl -f http://localhost:$CUSTOM_PORT/geoserver/web/ > /dev/null 2>&1; then
    print_status "SUCCESS" "GeoServer is responding on port $CUSTOM_PORT"
else
    print_status "WARNING" "GeoServer is not responding yet, checking logs..."
    podman logs geoserver-fips
fi

# Check FIPS mode in container
echo
echo "Checking FIPS mode in container..."
FIPS_CHECK=$(podman exec geoserver-fips java -Dcom.redhat.fips=true -cp "/opt/geoserver/lib/bcprov.jar:/opt/geoserver/lib/bcpkix.jar:/opt/geoserver/lib/fips-utils.jar" org.geoserver.security.FIPSKeyStoreProvider --detect 2>/dev/null || echo "FIPS_CHECK_FAILED")

if echo "$FIPS_CHECK" | grep -q "FIPS mode is active"; then
    print_status "SUCCESS" "FIPS mode is active in the container"
elif echo "$FIPS_CHECK" | grep -q "Available Security Providers"; then
    print_status "SUCCESS" "FIPS mode check completed (providers listed)"
    echo "$FIPS_CHECK"
else
    print_status "WARNING" "FIPS mode check failed or not detected"
    echo "$FIPS_CHECK"
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

# Test keystore operations
echo
echo "Testing keystore operations..."
podman exec geoserver-fips java -Dcom.redhat.fips=true -cp "/opt/geoserver/lib/bcprov.jar:/opt/geoserver/lib/bcpkix.jar:/opt/geoserver/lib/fips-utils.jar" org.geoserver.security.FIPSKeyStoreProvider --test

# Test keystore creation
echo
echo "Testing keystore creation..."
podman exec geoserver-fips bash -c '
cd /opt/geoserver
# Create a test keystore first using keytool with BC provider
keytool -genkeypair -alias test -keyalg RSA -keysize 2048 -keystore /tmp/test-keystore.p12 -storetype PKCS12 -storepass testpass -dname "CN=Test, OU=Test, O=Test, L=Test, ST=Test, C=US" -validity 365 -provider BC -providerpath /opt/geoserver/lib/bcprov.jar

# Test migration utility with correct classpath
java -Dcom.redhat.fips=true -cp "/opt/geoserver/lib/bcprov.jar:/opt/geoserver/lib/bcpkix.jar:/opt/geoserver/lib/fips-utils.jar" org.geoserver.security.MigrateKeystore --migrate --source /tmp/test-keystore.p12 --source-password testpass --target /tmp/test-keystore-new.p12 --target-password testpass --source-type PKCS12 --target-type BCFKS --verbose
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
if curl -f http://localhost:$CUSTOM_PORT/geoserver/rest/security/ > /dev/null 2>&1; then
    print_status "SUCCESS" "Security REST endpoint is accessible"
else
    print_status "WARNING" "Security REST endpoint is not accessible"
fi

echo
echo "=== FIPS Testing Complete ==="
echo
echo "To access GeoServer: http://localhost:$CUSTOM_PORT/geoserver"
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