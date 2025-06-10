import pandas as pd

csv_path = "all_sources/actual_vs_pred_20250606_121803.csv"

df = pd.read_csv(csv_path)

df['absolute_difference'] = (df['actual'] - df['predicted']).abs()

average_difference = df['absolute_difference'].mean()

print(f"Average Absolute Difference: {average_difference:.6f}")

def categorize(score):
    if score <= 0.1:
        return 'low'
    elif score <= 0.7:
        return 'medium'
    else:
        return 'high'

df['actual_category'] = df['actual'].apply(categorize)
df['predicted_category'] = df['predicted'].apply(categorize)

df['category_match'] = df['actual_category'] == df['predicted_category']
df['category_match'] = df['category_match'].map({True: 'yes', False: 'no'})

output_path = "analysis.csv"
df.to_csv(output_path, index=False)
print(f"Detailed analysis saved to {output_path}")