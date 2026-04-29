import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import sys
import os
import numpy as np

# Add parent directory to path to import app.features
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.features import get_feature_vector, FEATURE_NAMES

def train_model(dataset_path):
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset {dataset_path} not found.")
        sys.exit(1)

    print(f"[1/5] Loading dataset: {dataset_path}...")
    
    # Auto-detect format
    if dataset_path.endswith('.csv'):
        df = pd.read_csv(dataset_path)
        # Auto-detect columns
        cols = [c.lower().strip() for c in df.columns]
        url_col = None
        label_col = None
        
        for i, c in enumerate(cols):
            if c in ['url', 'urls', 'site', 'domain']:
                url_col = df.columns[i]
            if c in ['label', 'labels', 'result', 'target', 'class']:
                label_col = df.columns[i]
        
        if not url_col or not label_col:
            print("Error: Could not detect URL and Label columns.")
            sys.exit(1)
            
        # Map labels
        def map_label(val):
            val = str(val).lower().strip()
            if val in ['bad', 'phishing', '-1', '1.0', '-1.0']:
                return -1
            if val in ['good', 'legitimate', 'benign', '1', '0', '0.0']:
                return 1
            return None
            
        df['target'] = df[label_col].apply(map_label)
        df = df.dropna(subset=['target'])
        
    elif dataset_path.endswith('.arff'):
        # Simple ARFF parser for the @DATA section
        print("Parsing ARFF format...")
        data = []
        with open(dataset_path, 'r') as f:
            scanning = False
            for line in f:
                if line.lower().startswith('@data'):
                    scanning = True
                    continue
                if scanning and line.strip() and not line.startswith('%'):
                    data.append([int(x.strip()) for x in line.split(',')])
        
        df = pd.DataFrame(data)
        # For UCI ARFF, the last column is the result
        df.columns = FEATURE_NAMES + ['target'] if len(df.columns) == 31 else [f"f{i}" for i in range(len(df.columns)-1)] + ['target']
    else:
        print("Error: Unsupported file format. Use .csv or .arff")
        sys.exit(1)

    # Sample if large
    if len(df) > 50000:
        print(f"Sampling 50,000 rows from {len(df)}...")
        df = df.sample(n=50000, random_state=42)

    print(f"[2/5] Extracting features for {len(df)} rows...")
    # If it's CSV, we need to extract features from URLs
    if 'url' in locals() or url_col:
        X = []
        y = []
        total = len(df)
        for i, (idx, row) in enumerate(df.iterrows()):
            url = row[url_col]
            features = get_feature_vector(url, fast=True)
            X.append(features)
            y.append(row['target'])
            if (i+1) % 1000 == 0:
                print(f"  Processed {i+1}/{total} URLs...")
        X = np.array(X)
        y = np.array(y)
    else:
        # ARFF already has features
        X = df.drop('target', axis=1).values
        y = df['target'].values

    print("[3/5] Splitting data 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    print("[4/5] Training XGBoost Classifier...")
    clf = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )
    
    # Map y from [-1, 1] to [0, 1] for XGBoost internal logic if needed
    # but many XGB versions handle it. To be safe:
    y_train_mapped = np.where(y_train == -1, 1, 0) # Phishing=1, Legit=0
    y_test_mapped = np.where(y_test == -1, 1, 0)
    
    clf.fit(X_train, y_train_mapped)

    print("[5/5] Evaluating model...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test_mapped, y_pred)
    
    print("\nAccuracy Score:", acc)
    print("\nClassification Report:")
    print(classification_report(y_test_mapped, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test_mapped, y_pred))

    output_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
    print(f"\nSaving model to {output_path}...")
    
    model_data = {
        'model': clf,
        'features': FEATURE_NAMES,
        'accuracy': acc
    }
    
    joblib.dump(model_data, output_path)
    print("Training complete!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ml_model/train_model.py <dataset_path>")
        sys.exit(1)
        
    train_model(sys.argv[1])
