import pandas as pd

csv_path = "all_sources/actual_vs_pred_20250606_121803.csv"

df = pd.read_csv(csv_path)

df['absolute_difference'] = (df['predicted'] - df['actual']).abs()

average_difference = df['absolute_difference'].mean()

print(f"Average Absolute Difference: {average_difference:.6f}")

def categorize(score):
    if score <= 0.1:
        return 'low'
    elif score <= 0.7:
        return 'medium'
    else:
        return 'high'

def compare_scores(row):
    if row['actual_category'] == row['predicted_category']:
        return 'same'
    elif row['actual'] > row['predicted']:
        return 'higher'
    else:
        return 'lower'
    
df['predicted_category'] = df['predicted'].apply(categorize)
df['actual_category'] = df['actual'].apply(categorize)

df['category_match'] = df['actual_category'] == df['predicted_category']
df['category_match'] = df['category_match'].map({True: 'yes', False: 'no'})

df['score_comparison'] = df.apply(compare_scores, axis=1)

output_path = "analysis.csv"
df.to_csv(output_path, index=False)
print(f"Detailed analysis saved to {output_path}")