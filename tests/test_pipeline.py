"""Small smoke tests for the synthetic-data pipeline."""
from src.data import create_demo_dataset, clean_dataset, FEATURES, TARGET

def test_demo_dataset_schema_and_labels():
    df = create_demo_dataset(n_samples=300)
    assert list(df.columns) == FEATURES + [TARGET]
    assert set(df[TARGET].unique()) == {0, 1}
    assert len(df) == 300

def test_cleaning_removes_missing_labels():
    df = create_demo_dataset(n_samples=300)
    df.loc[0, TARGET] = float("nan")
    cleaned = clean_dataset(df)
    assert cleaned[TARGET].isna().sum() == 0
    assert set(cleaned[TARGET].unique()) == {0, 1}
