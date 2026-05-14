#!/bin/bash
# setup-azure.sh — One-time Azure Container App creation for ADFS Migration.
# Reuses the existing Container Apps Environment in your-resource-group, the
# existing your-acr-name ACR, and the workspace already attached to the
# Container Apps env. Adds a system-assigned managed identity with Log
# Analytics Reader role on that workspace so the /logs page can query KQL.
#
# Required env vars (or interactive prompts):
#   OKTA_DEV_TOKEN, OKTA_STG_TOKEN, OKTA_PROD_TOKEN
#   OIDC_CLIENT_ID_VAL         (PROD Okta "Okta Admin Tools" app client_id)
#   OIDC_CLIENT_SECRET_VAL     (PROD Okta "Okta Admin Tools" app client_secret)
#   OIDC_ISSUER_VAL            (PROD Okta authorization-server issuer URL)
#   FLASK_SECRET_KEY_VAL       (auto-generated if unset)

set -e

if [ -f "$HOME/.vpn-ca-bundle.pem" ]; then
  export REQUESTS_CA_BUNDLE="$HOME/.vpn-ca-bundle.pem"
fi
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

APP_NAME="adfs-okta-migration"
RESOURCE_GROUP="your-resource-group"
ACR="your-acr-name"
LA_WORKSPACE_RG="your-resource-group"
LA_WORKSPACE_NAME="workspace-federatedclaimsrg16IP"
LA_TABLE="ADFSImportRuns"
INITIAL_VERSION="v$(grep '^APP_VERSION' app.py | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${INITIAL_VERSION}"

echo "==========================================="
echo "  One-time setup for $APP_NAME"
echo "==========================================="

ENV_NAME=$(az containerapp env list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv)
if [ -z "$ENV_NAME" ]; then
  echo "ERROR: No Container Apps Environment found in $RESOURCE_GROUP."
  exit 1
fi
echo "Using Container Apps Environment: $ENV_NAME"

# Resolve LA workspace customerId + resource ID + shared key (for write).
SUB=$(az account show --query id -o tsv)
LA_RESOURCE_ID="/subscriptions/$SUB/resourceGroups/$LA_WORKSPACE_RG/providers/Microsoft.OperationalInsights/workspaces/$LA_WORKSPACE_NAME"
LA_WORKSPACE_ID=$(az rest --method get --url "https://host.example.gov}?api-version=2020-08-01" --query "properties.customerId" -o tsv)
LA_WORKSPACE_KEY=$(az rest --method post --url "https://host.example.gov}/sharedKeys?api-version=2020-08-01" --query "primarySharedKey" -o tsv)
echo "LA workspace: $LA_WORKSPACE_NAME (customerId=$LA_WORKSPACE_ID)"

echo ""
echo "Building initial image $INITIAL_VERSION in ACR..."
az acr build --registry "$ACR" --image "${APP_NAME}:${INITIAL_VERSION}" --file Dockerfile .

echo ""
echo "Fetching ACR admin credentials..."
ACR_PASSWORD=$(az acr credential show --name "$ACR" --query "passwords[0].value" -o tsv | tr -d '\r\n')

# ---------------------------------------------------------------------------
# Collect secrets
# ---------------------------------------------------------------------------
[ -z "${OKTA_DEV_TOKEN:-}" ]  && read -srp "Enter OKTA DEV  API token: "  OKTA_DEV_TOKEN  && echo
[ -z "${OKTA_STG_TOKEN:-}" ]  && read -srp "Enter OKTA STG  API token: "  OKTA_STG_TOKEN  && echo
[ -z "${OKTA_PROD_TOKEN:-}" ] && read -srp "Enter OKTA PROD API token: " OKTA_PROD_TOKEN && echo
[ -z "${OIDC_CLIENT_ID_VAL:-}" ]     && read -srp "Enter OIDC client_id: "     OIDC_CLIENT_ID_VAL  && echo
[ -z "${OIDC_CLIENT_SECRET_VAL:-}" ] && read -srp "Enter OIDC client_secret: " OIDC_CLIENT_SECRET_VAL && echo
[ -z "${OIDC_ISSUER_VAL:-}" ]        && read -rp  "Enter OIDC issuer URL: "    OIDC_ISSUER_VAL
[ -z "${FLASK_SECRET_KEY_VAL:-}" ]   && FLASK_SECRET_KEY_VAL=$(python3 -c "import secrets; print(secrets.token_hex(32))")

SECRETS=(
  "okta-dev-token=$OKTA_DEV_TOKEN"
  "okta-stg-token=$OKTA_STG_TOKEN"
  "okta-prod-token=$OKTA_PROD_TOKEN"
  "flask-secret-key=$FLASK_SECRET_KEY_VAL"
  "oidc-client-id=$OIDC_CLIENT_ID_VAL"
  "oidc-client-secret=$OIDC_CLIENT_SECRET_VAL"
  "oidc-issuer=$OIDC_ISSUER_VAL"
  "la-workspace-key=$LA_WORKSPACE_KEY"
)
ENV_VARS=(
  "OKTA_DEV_API_TOKEN=secretref:okta-dev-token"
  "OKTA_STG_API_TOKEN=secretref:okta-stg-token"
  "OKTA_PROD_API_TOKEN=secretref:okta-prod-token"
  "FLASK_SECRET_KEY=secretref:flask-secret-key"
  "OIDC_CLIENT_ID=secretref:oidc-client-id"
  "OIDC_CLIENT_SECRET=secretref:oidc-client-secret"
  "OIDC_ISSUER=secretref:oidc-issuer"
  "LA_WORKSPACE_ID=$LA_WORKSPACE_ID"
  "LA_WORKSPACE_KEY=secretref:la-workspace-key"
  "LA_TABLE_NAME=$LA_TABLE"
  "LA_RESOURCE_ID=$LA_RESOURCE_ID"
)

echo ""
echo "Creating Container App $APP_NAME..."
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$ENV_NAME" \
  --image "$IMAGE" \
  --registry-server "${ACR}.azurecr.io" \
  --registry-username "$ACR" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 1 \
  --cpu 0.5 \
  --memory 1.0Gi \
  --system-assigned \
  --secrets "${SECRETS[@]}" \
  --env-vars "${ENV_VARS[@]}"

FQDN=$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.configuration.ingress.fqdn" -o tsv)

az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --set-env-vars "APP_BASE_URL=https://host.example.gov" -o none

# ---------------------------------------------------------------------------
# Grant the Container App's MI Log Analytics Reader on the workspace so the
# /logs page can run KQL.
# ---------------------------------------------------------------------------
MI_PRINCIPAL_ID=$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "identity.principalId" -o tsv)
echo ""
echo "Granting Log Analytics Reader to MI ($MI_PRINCIPAL_ID)..."
az role assignment create \
  --assignee-object-id "$MI_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" \
  --scope "$LA_RESOURCE_ID" -o none || echo "  (role assignment may already exist — continuing)"

echo ""
echo "==========================================="
echo "  $APP_NAME created"
echo "  URL: https://host.example.gov"
echo ""
echo "  Next:"
echo "    1. Add this redirect URI to PROD Okta 'Okta Admin Tools' app:"
echo "       https://host.example.gov"
echo "    2. Backfill historical import logs (optional, one-time):"
echo "       LA_WORKSPACE_ID=$LA_WORKSPACE_ID LA_WORKSPACE_KEY='$LA_WORKSPACE_KEY' \\"
echo "         LA_TABLE_NAME=$LA_TABLE python3 backfill-logs.py logs/"
echo "    3. Subsequent deploys: ./deploy.sh <version>"
echo "==========================================="
