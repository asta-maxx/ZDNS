from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "final_up_data.csv"
MODEL_PATH = BASE_DIR / "best_naive_bayes_model.pkl"


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    # Handle possible unnamed index column
    if "" in df.columns:
        df = df.drop(columns=[""])
    if "url" not in df.columns or "type" not in df.columns:
        raise ValueError("Expected columns: url, type")

    df["url"] = df["url"].fillna("").astype(str)
    df = df[df["url"].str.len() > 0]
    df["type"] = df["type"].astype(int)

    X = df["url"]
    y = df["type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 4),
                    min_df=2,
                    max_features=50000,
                ),
            ),
            ("nb", MultinomialNB()),
        ]
    )

    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Saved pipeline model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
