#!/usr/bin/env bash
# Download the crop recommendation dataset (Kaggle "aksahaha/crop-recommendation", mirrored on Hugging Face).
set -euo pipefail
cd "$(dirname "$0")/../data"
curl -sL -o Crop_recommendation.csv \
  "https://huggingface.co/datasets/jason1966/aksahaha_crop-recommendation/resolve/main/Crop_recommendation.csv"
echo "Saved data/Crop_recommendation.csv ($(wc -l < Crop_recommendation.csv) lines)"
