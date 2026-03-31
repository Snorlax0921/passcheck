#!/bin/bash
# Usage: ./check_artifact_registry.sh PROJECT_ID LOCATION REPO_NAME IMAGE_NAME TAG [--run]
# Example: ./check_artifact_registry.sh temporal-fx-415304 asia-east1 passcheck passcheckimg 20260301 --run
# 改todotag 後面數字 submit
PROJECT_ID=$1
LOCATION=$2
REPO=$3
IMAGE=$4
TAG=$5
RUN_FLAG=$6

if [ -z "$PROJECT_ID" ] || [ -z "$LOCATION" ] || [ -z "$REPO" ] || [ -z "$IMAGE" ] || [ -z "$TAG" ]; then
  echo "❌ 用法: $0 PROJECT_ID LOCATION REPO_NAME IMAGE_NAME TAG [--run]"
  exit 1
fi

FULL_PATH="$LOCATION-docker.pkg.dev/$PROJECT_ID/$REPO/$IMAGE:$TAG"

echo "=== 1. 目前 gcloud 帳號 ==="
gcloud auth list

echo
echo "=== 2. gcloud config project ==="
gcloud config get-value project

echo
echo "=== 3. 確認 Docker credential helper ==="
cat ~/.docker/config.json | grep "$LOCATION-docker.pkg.dev" -A 2 || echo "⚠️ 未設定 credHelpers"

echo
echo "=== 4. 確認 repo 是否存在 ==="
gcloud artifacts repositories describe $REPO \
  --location=$LOCATION \
  --project=$PROJECT_ID || echo "⚠️ 找不到 repo: $REPO"

echo
echo "=== 5. 檢查 IAM 權限 (Cloud Build SA) ==="
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
SA="$PROJECT_NUMBER@cloudbuild.gserviceaccount.com"
echo "服務帳號: $SA"

gcloud projects get-iam-policy $PROJECT_ID \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.members:serviceAccount:$SA"

echo
echo "=== 6. 檢查 image/tag 是否已存在 (避免 immutable-tags 衝突) ==="
gcloud artifacts docker images describe $FULL_PATH \
  --project=$PROJECT_ID \
  || echo "✅ tag $TAG 尚未存在，可以安全上傳"

echo
echo "=== 7. 建議的上傳指令 (Cloud Build) ==="
echo "gcloud builds submit --tag $FULL_PATH"

# 如果加上 --run，直接執行 gcloud builds submit
if [ "$RUN_FLAG" == "--run" ]; then
  echo
  echo "🚀 執行上傳..."
  gcloud builds submit --tag $FULL_PATH
fi
