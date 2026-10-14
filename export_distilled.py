import json, joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import train
from feature_extractor import FEATURE_NAMES

df = train.load_dataset()
df = pd.concat([df, train.build_trusted_augmentation()], ignore_index=True)
df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
X, y = train.build_feature_matrix(df)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
m = RandomForestClassifier(n_estimators=50, max_depth=10, min_samples_leaf=25,
                           n_jobs=-1, random_state=42, class_weight="balanced")
m.fit(Xtr, ytr)
print("test acc", round(accuracy_score(yte, m.predict(Xte)), 4))

trees = []
for est in m.estimators_:
    t = est.tree_
    value = []
    for i in range(t.node_count):
        c = t.value[i][0]
        value.append(round(float(c[1] / c.sum()), 4) if c.sum() > 0 else 0.5)
    trees.append({"feature": t.feature.tolist(),
                  "threshold": [round(float(x), 5) for x in t.threshold],
                  "left": t.children_left.tolist(),
                  "right": t.children_right.tolist(),
                  "value": value})
json.dump({"feature_names": FEATURE_NAMES, "n_trees": len(trees), "trees": trees},
          open(__import__("pathlib").Path(__file__).resolve().parent.parent / "model" / "distilled_forest.json", "w"), separators=(",", ":"))
print("nodes", sum(len(t["feature"]) for t in trees))
