import pandas as pd

df = pd.read_csv('../data/cicids2017.csv')

print("Shape:", df.shape)
print("\nAttack Type counts:\n", df['Attack Type'].value_counts())
print("\nMissing values:", df.isnull().sum().sum())
print("\nFirst 3 rows:\n", df.head(3))