# Pre-Classifier v1 (TF-IDF + LogisticRegression)

- Train set: `data/ml_training/preclf_train.jsonl` (140 samples)
- Eval set: `data/ml_training/preclf_eval.jsonl` (35 samples)
- Model path: `models/preclf_v1.joblib`

## Eval Metrics
- Accuracy: 0.8857
- F1 (macro): 0.8604

Per label (precision / recall / f1):
- educational: 0.900 / 0.947 / 0.923
- command: 1.000 / 0.800 / 0.889
- text: 0.714 / 0.833 / 0.769

## Training Command
```bash
python scripts/train_preclassifier.py \
  --train data/ml_training/preclf_train.jsonl \
  --eval data/ml_training/preclf_eval.jsonl \
  --output models/preclf_v1.joblib
```

## Runtime Env (enable ML in pipeline)
- `FEATURE_ML_PRECLF=true`
- `PRECLF_MODEL_PATH=models/preclf_v1.joblib`

## Observability
- Metrics include `egress_guard_ml_preclf_load_total{status}` to see load success/fail.

## Notes
- Features: TF-IDF (1-2 grams), min_df=2, max_features=50k, class_weight=balanced.
- Uses `segment_type`/`language` tokens prepended into text for better separation.
- Fallback: Parser still uses heuristic if model load fails.

