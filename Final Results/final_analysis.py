import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

csv_path = "../final_plots_sbert_0_alpha/only_bleepingcomputer/actual_vs_pred_20250614_120607.csv"

df = pd.read_csv(csv_path)
df['absolute_difference'] = (df['predicted'] - df['actual']).abs()
average_difference = df['absolute_difference'].mean()

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
df['within_10_percent'] = (df['absolute_difference'] <= 0.1 * df['predicted'])
df['within_20_percent'] = (df['absolute_difference'] <= 0.2 * df['predicted'])

output_path = "analysis.csv"
df.to_csv(output_path, index=False)
print(f"Detailed analysis saved to {output_path}")

match_rate = (df['category_match'] == 'yes').mean()
comparison_counts = df['score_comparison'].value_counts().to_dict()

accuracy = accuracy_score(df['actual_category'], df['predicted_category'])
report = classification_report(df['actual_category'], df['predicted_category'], output_dict=True)

macro_precision = report['macro avg']['precision']
macro_recall = report['macro avg']['recall']
macro_f1 = report['macro avg']['f1-score']

weighted_precision = report['weighted avg']['precision']
weighted_recall = report['weighted avg']['recall']
weighted_f1 = report['weighted avg']['f1-score']

summary_lines = [
    f"Average Absolute Difference: {average_difference:.6f}",
    f"Category Match Rate: {match_rate:.2%}",
    "",
    "Score Comparison Breakdown:"
]

for comp, count in comparison_counts.items():
    summary_lines.append(f"  {comp.capitalize()}: {count}")

summary_lines.extend([
    "",
    f"Accuracy: {accuracy:.2%}",
    f"Macro Precision: {macro_precision:.4f}",
    f"Macro Recall: {macro_recall:.4f}",
    f"Macro F1 Score: {macro_f1:.4f}",
    "",
    f"Weighted Precision: {weighted_precision:.4f}",
    f"Weighted Recall: {weighted_recall:.4f}",
    f"Weighted F1 Score: {weighted_f1:.4f}",
    ""
])

pct_within_10 = df['within_10_percent'].mean()
pct_within_20 = df['within_20_percent'].mean()

summary_lines.append(f"Within 10% Rate: {pct_within_10:.2%}")
summary_lines.append(f"Within 20% Rate: {pct_within_20:.2%}")

with open("analysis_summary.txt", "w") as f:
    f.write("\n".join(summary_lines))

print("Summary text saved to analysis_summary.txt")

rates = {'Within 10%': pct_within_10 * 100, 'Within 20%': pct_within_20 * 100}
plt.figure()
plt.bar(rates.keys(), rates.values())
plt.ylim(0, 100)
plt.ylabel('Percentage')
plt.title('Percentage of Values Within Thresholds')
plt.tight_layout()
plt.savefig('within_thresholds.png')
plt.show()

labels = ['high', 'medium', 'low']
cm = confusion_matrix(df['actual_category'], df['predicted_category'], labels=labels)

comparison_counts = df['score_comparison'].value_counts()
comparison_counts.plot(kind='bar', title='Score Comparison Breakdown', ylabel='Count')
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig('score_comparison_breakdown.png')
plt.show()

plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.tight_layout()
plt.savefig('confusion_matrix.png')
plt.show()

df['absolute_difference'].plot(kind='hist', bins=30, title='Distribution of Absolute Differences')
plt.xlabel('Absolute Difference')
plt.tight_layout()
plt.savefig('absolute_difference_hist.png')
plt.show()