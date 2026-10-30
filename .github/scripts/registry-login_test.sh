#!/usr/bin/env bash
# Runs registry-login/action.yml's "Which cloud" step, as the action has
# it, and checks that one cloud's complete inputs and a registry of that
# cloud pick it (with the ECR account and region, or the ACR name, read
# from the registry), and that anything else fails before logging in.
#
# Usage: .github/scripts/registry-login_test.sh (needs bash and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
yq -e '.runs.steps[] | select(.name == "Which cloud") | .run' "$root/registry-login/action.yml" > "$tmp/step.sh"

fail=0
# registry|aws-role|aws-region|gcp-provider|gcp-account|azure-client|azure-tenant|azure-subscription|want (outputs, or "error: …")
while IFS='|' read -r registry role region provider account client tenant subscription want; do
  : > "$tmp/output"
  if REGISTRY=$registry AWS_ROLE=$role AWS_REGION_INPUT=$region GCP_PROVIDER=$provider GCP_ACCOUNT=$account \
    AZURE_CLIENT=$client AZURE_TENANT=$tenant AZURE_SUBSCRIPTION=$subscription GITHUB_OUTPUT=$tmp/output \
    bash --noprofile --norc -eo pipefail "$tmp/step.sh" > "$tmp/log" 2>&1; then
    got=$(sort "$tmp/output" | paste -sd' ' -)
  else
    got="error: $(sed -n 's/^::error::registry login: //p' "$tmp/log")"
  fi
  case "$want" in
    error:*) ok=false; [[ "$got" == "$want"* ]] && ok=true ;;
    *) ok=false; [ "$got" = "$want" ] && ok=true ;;
  esac
  if ! $ok; then
    echo "FAIL: $registry ($role$provider$client): got '$got', want '$want'"
    fail=1
  fi
done <<'CASES'
123456789012.dkr.ecr.eu-west-1.amazonaws.com|arn:aws:iam::123456789012:role/publish|||||||account=123456789012 cloud=aws region=eu-west-1
123456789012.dkr.ecr.eu-west-1.amazonaws.com/team|arn:aws:iam::123456789012:role/publish|us-east-1||||||account=123456789012 cloud=aws region=us-east-1
123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn|arn:aws-cn:iam::123456789012:role/publish|||||||account=123456789012 cloud=aws region=cn-north-1
ghcr.io|arn:aws:iam::123456789012:role/publish|||||||error: ghcr.io is not an Amazon ECR registry
123456789012.dkr.ecr.eu-west-1.amazonaws.com.evil.example|arn:aws:iam::123456789012:role/publish|||||||error: 123456789012.dkr.ecr.eu-west-1.amazonaws.com.evil.example is not an Amazon ECR registry
123456789012.dkr.ecr.eu-west-1.amazonaws.com||eu-west-1||||||error: aws-region needs aws-role-arn
europe-docker.pkg.dev|||projects/1/locations/global/workloadIdentityPools/gh/providers/gh|publish@acme.iam.gserviceaccount.com||||cloud=gcp
europe-docker.pkg.dev|||projects/1/locations/global/workloadIdentityPools/gh/providers/gh|||||error: set both gcp-workload-identity-provider and gcp-service-account
docker.io|||projects/1/locations/global/workloadIdentityPools/gh/providers/gh|publish@acme.iam.gserviceaccount.com||||error: docker.io is not a Google Artifact Registry
acme.azurecr.io|||||client|tenant|subscription|cloud=azure name=acme
acme.azurecr.io|||||client|tenant||error: set azure-client-id, azure-tenant-id, and azure-subscription-id
acme.azurecr.io.evil.example|||||client|tenant|subscription|error: acme.azurecr.io.evil.example is not an Azure Container Registry
acme.azurecr.io|arn:aws:iam::123456789012:role/publish||||client|tenant|subscription|error: inputs for more than one cloud are set (aws azure)
ghcr.io||||||||error: set aws-role-arn
CASES
if [ "$fail" = 0 ]; then
  echo "registry-login: ok"
fi
exit "$fail"
