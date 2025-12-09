#!/bin/bash

echo "🚀 Starting Neo4j Dashboard Infrastructure Setup..."
echo "   This script will RESTART all containers and perform full setup."

# --- Environment Variables ---
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5433
export POSTGRES_NAME=neo_dashboard
export POSTGRES_USER=neo4j_dashboard_user
export POSTGRES_PASSWORD=Milad1986

export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=Milad1986

export MONGODB_HOST=localhost
export MONGODB_PORT=27017
export MONGODB_USER=mongodb_user
export MONGODB_PASSWORD=Milad1986
export MONGODB_DB=testcases_db

export DEBUG=True
export SECRET_KEY='django-insecure-sx42i2cydw$405*%s0e_*rwr@t&ixl_6h53*dr0c9+#itt^z6y'

# Keycloak Configuration
export KEYCLOAK_ENABLED=True
export KEYCLOAK_SERVER_URL=http://localhost:8080
export KEYCLOAK_REALM=neo4j_dashboard
export KEYCLOAK_CLIENT_ID=neo4j_dashboard_client
export KEYCLOAK_CLIENT_SECRET=neo4j_dashboard_secret
export KC_CONTAINER="neo4j_dashboard_keycloak"
export KC_ADMIN_USER="admin"
export KC_ADMIN_PASS="admin"
export REDIRECT_URI_LOCALHOST="http://localhost:8000/oidc/callback/"
export REDIRECT_URI_IP="http://127.0.0.1:8000/oidc/callback/"

echo "✅ Environment variables set."
echo ""

# --- Docker Containers Setup (FORCE RECREATE) ---
echo "📦 Restarting Core Docker Containers..."
# Force recreate to ensure fresh state as requested
# Now including wiremock in the main compose group
docker-compose up -d --force-recreate postgres neo4j mongodb wiremock
sleep 3

# --- Wiremock Setup ---
echo "📦 Checking Wiremock Setup..."
mkdir -p ./wiremock_mappings
# Wiremock is now started by docker-compose above
echo "   Waiting for Wiremock..."
sleep 5

# --- Keycloak Setup ---
if [ "$KEYCLOAK_ENABLED" = "True" ]; then
    echo "🔐 Restarting Keycloak Containers..."
    docker-compose --profile keycloak up -d --force-recreate keycloak keycloak-db

    echo "⏳ Waiting for Keycloak to be ready..."
    count=0
    KC_READY=false
    while [ $count -lt 60 ]; do
        if curl -s $KEYCLOAK_SERVER_URL > /dev/null; then
            KC_READY=true
            break
        fi
        sleep 2
        count=$((count+1))
        echo -n "."
    done
    echo ""

    if [ "$KC_READY" = "true" ]; then
        echo "   Keycloak is ready. Configuring..."
        
        # Helper alias for kcadm.sh inside the container
        KCADM="docker exec -i $KC_CONTAINER /opt/keycloak/bin/kcadm.sh"
        
        # Authenticate
        $KCADM config credentials --server http://localhost:8080 --realm master --user $KC_ADMIN_USER --password $KC_ADMIN_PASS
        
        # Create Realm
        if ! $KCADM get realms/$KEYCLOAK_REALM > /dev/null 2>&1; then
            echo "   📦 Creating realm '$KEYCLOAK_REALM'..."
            $KCADM create realms -s realm=$KEYCLOAK_REALM -s enabled=true
        else
            echo "   ✅ Realm '$KEYCLOAK_REALM' already exists."
        fi
        
        # Create/Update Client
        if ! $KCADM get clients -r $KEYCLOAK_REALM -q clientId=$KEYCLOAK_CLIENT_ID | grep -q "$KEYCLOAK_CLIENT_ID"; then
            echo "   📦 Creating client '$KEYCLOAK_CLIENT_ID'..."
            $KCADM create clients -r $KEYCLOAK_REALM -s clientId=$KEYCLOAK_CLIENT_ID -s enabled=true \
                -s clientAuthenticatorType=client-secret \
                -s secret=$KEYCLOAK_CLIENT_SECRET \
                -s redirectUris="[\"$REDIRECT_URI_LOCALHOST\", \"$REDIRECT_URI_IP\"]" \
                -s webOrigins="[\"http://localhost:8000\", \"http://127.0.0.1:8000\"]" \
                -s 'attributes."post.logout.redirect.uris"="+"' \
                -s frontchannelLogout=true \
                -s standardFlowEnabled=true \
                -s directAccessGrantsEnabled=true \
                -s publicClient=false \
                -s protocol=openid-connect
        else
            echo "   🔄 Updating existing client to ensure redirect URLs..."
            CLIENT_UUID=$($KCADM get clients -r $KEYCLOAK_REALM -q clientId=$KEYCLOAK_CLIENT_ID --fields id --format csv --noquotes)
            $KCADM update clients/$CLIENT_UUID -r $KEYCLOAK_REALM \
                -s redirectUris="[\"$REDIRECT_URI_LOCALHOST\", \"$REDIRECT_URI_IP\"]" \
                -s webOrigins="[\"http://localhost:8000\", \"http://127.0.0.1:8000\"]" \
                -s 'attributes."post.logout.redirect.uris"="+"' \
                -s frontchannelLogout=true
        fi
        
        # Create Test User
        TEST_USER="testuser"
        USER_CHECK=$($KCADM get users -r $KEYCLOAK_REALM -q username=$TEST_USER 2>/dev/null | tr -d '[:space:]')
        if [ "$USER_CHECK" = "[]" ]; then
            echo "   👤 Creating Keycloak test user '$TEST_USER'..."
            $KCADM create users -r $KEYCLOAK_REALM -s username=$TEST_USER -s enabled=true -s email="test@example.com" -s firstName="Test" -s lastName="User"
            $KCADM set-password -r $KEYCLOAK_REALM --username $TEST_USER --new-password "password"
            echo "   ✅ User created (pass: password)."
        else
            echo "   ✅ User '$TEST_USER' already exists."
        fi
        
        # Create Admin User in Realm (matching Django superuser)
        ADMIN_USER="admin"
        ADMIN_CHECK=$($KCADM get users -r $KEYCLOAK_REALM -q username=$ADMIN_USER 2>/dev/null | tr -d '[:space:]')
        if [ "$ADMIN_CHECK" = "[]" ]; then
            echo "   👤 Creating Keycloak admin user '$ADMIN_USER'..."
            $KCADM create users -r $KEYCLOAK_REALM -s username=$ADMIN_USER -s enabled=true -s email="admin@example.com" -s firstName="Admin" -s lastName="User"
            $KCADM set-password -r $KEYCLOAK_REALM --username $ADMIN_USER --new-password "admin123"
            echo "   ✅ Admin user created in Keycloak (pass: admin123)."
        else
            echo "   ✅ User '$ADMIN_USER' already exists."
        fi
        echo "   ✨ Keycloak configuration complete!"
    else
        echo "❌ Keycloak did not start in time. Skipping configuration."
    fi
fi
echo ""

# --- Postgres Port Check ---
POSTGRES_PORT_CHECK=$(docker port neo4j_dashboard_postgres 2>/dev/null | grep -o "5433" || echo "")
if [ -z "$POSTGRES_PORT_CHECK" ]; then
    echo "⚠️  PostgreSQL container is on wrong port. Restarting with correct port..."
    docker-compose up -d --force-recreate postgres
    sleep 5
fi

# --- Verify Postgres ---
echo "🔍 Verifying PostgreSQL setup..."
sleep 2
if docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -c "SELECT 1;" &>/dev/null 2>&1; then
    DB_EXISTS=$(docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='neo_dashboard'" 2>/dev/null | tr -d ' ' || echo "")
    if [ "$DB_EXISTS" != "1" ]; then
        echo "   ⚠️  Database 'neo_dashboard' not found. Creating..."
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -c "CREATE DATABASE neo_dashboard;" 2>/dev/null
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d neo_dashboard -c "GRANT ALL PRIVILEGES ON DATABASE neo_dashboard TO neo4j_dashboard_user;" 2>/dev/null
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d neo_dashboard -c "GRANT ALL PRIVILEGES ON SCHEMA public TO neo4j_dashboard_user;" 2>/dev/null
    else
        echo "   ✅ PostgreSQL is ready"
    fi
else
    echo "❌ Cannot connect to PostgreSQL. Please check logs."
    exit 1
fi
echo ""

# --- App Setup ---
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

echo "🔧 Activating virtual environment..."
source venv/bin/activate

echo "📥 Installing dependencies..."
pip install -r requirements.txt

echo "🗄️ Running migrations..."
python manage.py migrate

echo "👤 Setting up admin user..."
python manage.py shell << 'PYEOF'
from django.contrib.auth import get_user_model
User = get_user_model()
try:
    admin, created = User.objects.get_or_create(username='admin', defaults={'email': 'admin@example.com', 'role': 3, 'is_approved': True, 'is_staff': True, 'is_superuser': True, 'is_active': True})
    if created:
        admin.set_password('admin123')
        print("   ✅ Admin user created (admin/admin123)")
    else:
        admin.set_password('admin123')
        print("   ✅ Admin user password reset to 'admin123'")
    admin.save()
except Exception as e:
    print(f"   ⚠️  Error setting up admin user: {e}")
PYEOF

echo ""
echo "✨ Infrastructure Setup Complete!"
echo ""
echo "👉 To start the server, run: ./run_local.sh"
echo ""
