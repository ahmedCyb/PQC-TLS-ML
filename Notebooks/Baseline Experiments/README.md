Use this folder to record experiments on the original dataset without feature engineering.

Experiment 1 (Random Forest with no feature enginnering):
the model took 1 second to train 0.20 secoond to test, amazing results on the normal class with 98 precision and 100 recall. 97 precision and 83 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](01_random_forest_original.ipynb)

Experiment 2 (Extra Trees with no feature enginnering):
the model took 0.95 seconds to train 0.27 secoonds to test, almost perfect results on the normal class with 98 precision and 99 recall. 94 precision and 83 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](04_extra_trees_original.ipynb)

Experiment 3 (XGBoost with no feature enginnering):
the model took 0.19 seconds to train 0.01 secoonds to test, almost perfect results on the normal class with 98 precision and 100 recall. 100 precision and 82 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](xgb.ipynb)

Experiment 4 (LightGBM with no feature enginnering):
the model took 2 seconds to train 0.28 secoonds to test, almost perfect results on the normal class with 98 precision and 100 recall. 97 precision and 83 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](11_lightgbm_original.ipynb)

Experiment 5 (XGBoost with Weighted scales):
the model took 0.86 seconds to train 0.01 secoonds to test, almost perfect results on the normal class with 98 precision and 98 recall. 88 precision and 84 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](XGB+Weighted_Scale.ipynb)

Experiment 6 (LightGBM with RandomSearchCV):
the model took 2 seconds to train 0.30 secoonds to test, amazing results on the normal class with 98 precision and 99 recall. 90 precision and 83 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](LightGBM+RandomizedSearchCV.ipynb)

Experiment 7 (HistogramGradientBoosting with no feature enginnering):
the model took 0.98 seconds to train 0.09 secoonds to test, almost perfect results on the normal class with 98 precision and 100 recall. 100 precision and 82 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](06_hist_gradient_boosting.ipynb)

Experiment 8 (GradientBoosting with no feature enginnering):
the model took 8.66 seconds to train 0.07 secoonds to test, almost perfect results on the normal class with 99 precision and 98 recall. 88 precision and 90 recall on the anomaly class. we got good balance between them. [Chech out the full notebook](gradientboosting_original.ipynb)

Experiment 9 (CatBoost with no feature enginnering):
the model took 6.04 seconds to train 0.03 secoonds to test, almost perfect results on the normal class with 99 precision and 98 recall. 89 precision and 90 recall on the anomaly class. we got good balance between them. [Chech out the full notebook](41_catboost_original (1).ipynb)

Experiment 10 (AdaBoost with no feature enginnering):
the model took 4.69 seconds to train 0.41 secoonds to test, almost perfect results on the normal class with 100 precision and 97 recall. 83 precision and 100 recall on the anomaly class. we need better balance between them. [Chech out the full notebook](adaboost_original.ipynb)

Experiment 11 (Bagging with no feature enginnering):
the model took 15.38 seconds to train 1.56 secoonds to test, almost perfect results on the normal class with 99 precision and 98 recall. 89 precision and 90 recall on the anomaly class. we got good balance between them. [Chech out the full notebook](bagging_original.ipynb)
