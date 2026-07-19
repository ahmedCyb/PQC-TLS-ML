import pandas as pd
import numpy as np 
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from xgboost import XGBRegressor


data_set = pd.read_csv("/home/zeus/Projects/PQC-TLS-ML/Data/ml_features_and_labels.csv")
data_set.fillna(data_set.mean())
#data_set.dropna(axis=0,subset=['label'])
X = data_set
y = data_set['label']
X.drop(['label'],axis=1)

data_model = RandomForestRegressor(n_estimators=100)

X_train,X_val,y_train,y_val = train_test_split(X,y,test_size=0.8, random_state=0)

data_model.fit(X_train,y_train)

data_model.predict(y_val)

