#!/bin/bash
# deploy.sh — Build and deploy ADFS Migration to Azure Container Apps.
# Usage: ./deploy.sh [version_tag]   (e.g. ./deploy.sh v2.0.0)

set -e

if [ -f "$HOME/.vpn-ca-bundle.pem" ]; then
  export REQUESTS_CA_BUNDLE="$HOME/.vpn-ca-bundle.pem"
fi
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

APP_NAME="adfs-okta-migration"
RESOURCE_GROUP="your-resource-group"
ACR="your-acr-name"

VERSION="${1}"
if [ -z "$VERSION" ]; then
  read -rp "Enter version tag (e.g. v2.0.0): " VERSION
fi
if [ -z "$VERSION" ]; then
  echo "ERROR: Version tag is required. Aborting."
  exit 1
fi
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${VERSION}"

echo "==========================================="
echo "  Deploying $APP_NAME $VERSION"
echo "  Image: $IMAGE"
echo "==========================================="

echo ""
echo "Building image in ACR ($ACR)..."
az acr build --registry "$ACR" --image "${APP_NAME}:${VERSION}" --file Dockerfile .
echo "Build complete: $IMAGE"
echo ""

echo "Updating Container App to new image..."
az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --image "$IMAGE"

FQDN=$(az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)

echo ""
echo "==========================================="
echo "  Deployment complete: $IMAGE"
[ -n "$FQDN" ] && echo "  URL: https://host.example.gov"
echo ""
echo "  Note: my-aca-environment cold-pulls new revisions for 5-8 min."
echo "==========================================="
