import pandas as pd
import numpy as np 
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split

data_set = pd.read_csv("/home/zeus/Projects/PQC-TLS-ML/Data/ml_features_and_labels.csv")
data_set.fillna(data_set.mean())
y = data_set['label']
X = (data_set.drop(['label']))

data_model = RandomForestRegressor(n_estimators=100)

X_train,X_val,y_train,y_val = train_test_split(X,y,test_size=0.33, random_state=42)

data_model.fit(X_train,y_train)

data_model.predict(X_val)

