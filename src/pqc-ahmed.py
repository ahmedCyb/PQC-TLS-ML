import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split

path = ""
data_set = pd.read_csv(path)

# Fill missing values
data_set = data_set.fillna(data_set.mean(numeric_only=True))

y = data_set["label"]
X = data_set.drop(columns=["label"])

X_train, X_val, y_train, y_val = train_test_split(
    X, y, test_size=0.33, random_state=42
)

model = RandomForestRegressor(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_val)

mae = mean_absolute_error(y_val, predictions)
print("MAE:", mae)
