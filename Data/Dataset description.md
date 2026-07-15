# Dataset description

## Files and directory structure

The dataset consists of three primary files that provide different levels of granularity for researchers:

*   **ml_features_and_labels.csv**: The "ML-Ready" matrix. Contains the 32 engineered numerical features, one-hot encoded context vectors, and ground-truth labels used for training the LSTM/Autoencoder models.
*   **scenario_manifest.csv**: The experiment metadata. Maps every session ID to its specific testbed scenario (e.g., net_high_jitter_classic_run1), allowing for stratified performance analysis.
