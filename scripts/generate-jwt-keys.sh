# ==============================================================================
# SCRIPT DE GÉNÉRATION DES CLÉS JWT
# File: scripts/generate-jwt-keys.sh
# ==============================================================================
#!/bin/bash

# Génération des clés RSA pour JWT
echo "Génération des clés JWT pour OAuth2 Identity Service..."

# Créer le répertoire keys s'il n'existe pas
mkdir -p keys

# Générer la clé privée RSA (2048 bits)
openssl genrsa -out keys/jwt-private-key.pem 2048

# Générer la clé publique correspondante
openssl rsa -in keys/jwt-private-key.pem -pubout -out keys/jwt-public-key.pem

# Générer un keystore PKCS12 pour Spring Security
openssl pkcs12 -export -in keys/jwt-public-key.pem -inkey keys/jwt-private-key.pem \
  -out keys/jwt-keystore.p12 -name ndinga-eats-jwt \
  -passout pass:ndinga-eats-2024

# Définir les permissions appropriées
chmod 600 keys/jwt-private-key.pem
chmod 644 keys/jwt-public-key.pem
chmod 600 keys/jwt-keystore.p12

echo "Clés JWT générées avec succès dans le répertoire keys/"
echo "- Clé privée: keys/jwt-private-key.pem"
echo "- Clé publique: keys/jwt-public-key.pem"
echo "- Keystore: keys/jwt-keystore.p12"

# ==============================================================================
# TESTS D'INTÉGRATION OAUTH2
# File: tests/oauth2-integration-test.sh
# ==============================================================================
#!/bin/bash

BASE_URL="https://auth.staging.ndinga-eats.com"
CLIENT_ID="ndinga-eats-web-client"
CLIENT_SECRET="your-client-secret"

echo "🔐 Tests d'intégration OAuth2 Identity Service"
echo "============================================="

# Test 1: Récupération des métadonnées OpenID Connect
echo "1. Test des métadonnées OpenID Connect..."
curl -s "$BASE_URL/.well-known/openid_configuration" | jq .

# Test 2: Récupération des clés JWKS
echo -e "\n2. Test des clés JWKS..."
curl -s "$BASE_URL/.well-known/jwks.json" | jq .

# Test 3: Authorization Code Flow
echo -e "\n3. Test Authorization Code Flow..."
AUTH_URL="$BASE_URL/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=https://app.staging.ndinga-eats.com/auth/callback&scope=openid%20profile%20email&state=xyz"
echo "URL d'autorisation: $AUTH_URL"

# Test 4: Client Credentials Flow
echo -e "\n4. Test Client Credentials Flow..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=read")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
echo "Access Token obtenu: ${ACCESS_TOKEN:0:50}..."

# Test 5: Introspection du token
echo -e "\n5. Test d'introspection du token..."
curl -s -X POST "$BASE_URL/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN" | jq .

# Test 6: UserInfo endpoint
echo -e "\n6. Test UserInfo endpoint..."
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$BASE_URL/userinfo" | jq .

# Test 7: Health check
echo -e "\n7. Test Health check..."
curl -s "$BASE_URL/actuator/health" | jq .

echo -e "\n✅ Tests terminés!"