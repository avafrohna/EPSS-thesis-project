import pandas as pd

csv_path = "all_sources/actual_vs_pred_20250606_121803.csv"

df = pd.read_csv(csv_path)

df['absolute_difference'] = (df['actual'] - df['predicted']).abs()

average_difference = df['absolute_difference'].mean()

print(f"Average Absolute Difference: {average_difference:.6f}")

output_path = "analysis.csv"
summary_df = pd.DataFrame({'average_absolute_difference': [average_difference]})
summary_df.to_csv(output_path, index=False)
print(f"Analysis saved to {output_path}")