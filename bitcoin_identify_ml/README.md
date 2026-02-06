# Bitcoin traffic detection + attacker-centric victim identification

This repo contains a Wi‑Fi traffic analysis pipeline that:

- Trains a **per-window traffic classifier** using a fixed 50D feature extractor (sizes/timing/direction/MAC stats) and **XGBoost**.
- Runs an **attacker-centric evaluation** that simulates multi-user Wi‑Fi scenarios and ranks users by **Bitcoin likelihood** (`p(bitcoinsta)`), under increasing background-app mixing levels \(k=0..5\).

The core learning algorithm (feature extraction + XGBoost) is unchanged; the experiments focus on **Bitcoin detection and victim identification under mixed traffic**.

## Dataset format (current)

The dataset must be under `data/` as **flat JSON files**:

- Each `data/*.json` file is treated as a **distinct application class** (class id = filename stem).
- **Bitcoin class (currently)**: `bitcoinsta` (from `data/bitcoinsta.json`). At the moment, Bitcoin traffic in this dataset is **only** `bitcoinsta`.
- **Background classes (current `data/` snapshot)**:
  - `download` (`data/download.json`)
  - `game` (`data/game.json`)
  - `music` (`data/music.json`)
  - `video` (`data/video.json`)
  - `web` (`data/web.json`)

If you add more `data/*.json` files later, they will automatically become additional classes.

Each JSON file must be a list of packets with (at least) these fields:

- `ts` (float timestamp)
- `phy_len`, `mac_len`, `enc_payload_len` (ints)
- `sa`, `da`, `bssid` (MAC strings)
- `type`, `subtype` (ints)
- `protected`, `retry` (0/1)
- `direction` (`"tx"`/`"rx"`)
- `rssi` (int/float)

## Recommended environment (conda)

On macOS, some “framework Python” installs can segfault with NumPy/OpenBLAS. This repo is validated using conda.

```bash
conda create -n wifi_btc python=3.10 -y
conda activate wifi_btc
conda install -c conda-forge numpy pandas scikit-learn xgboost joblib matplotlib -y
```

## Quick start

### 1) Train + basic held-out mixture check (single script)

```bash
python -u bitcoin_detector.py
```

This trains a **multi-class** XGBoost model over `data/*.json` (pure windows) and runs a basic held-out mixture sweep. It also saves:

- `wifi_multiclass_model.pkl`

### 2) Attacker-centric “victim identification” experiment (recommended)

```bash
python -u -m experiments.run --config experiments/config_example.json
```

This simulates scenarios with:

- **N users** (configurable; e.g., N=5/10/20)
- **Num background apps (k)** = number of concurrent background app types mixed with Bitcoin for Bitcoin users (k=0..5)
- A subset of users running Bitcoin; others are non-Bitcoin-only

The attacker outputs a **per-user Bitcoin likelihood score**, ranks users, and reports user-level detection/ranking metrics.

## Architecture and Pipeline (current)

There are two entry points:

- `bitcoin_detector.py`: trains the **multi-class** per-window classifier on pure windows from each `data/*.json`.
- `python -m experiments.run ...`: runs the **attacker-centric** victim identification evaluation on held-out test data.

High-level flow:

```text
data/*.json (each file = one class)
  └─> leakage-safe time split per class (train/test by timestamp)
      ├─> windowing (200ms window, 100ms step, min 10 frames)
      │    └─> 50D feature extraction
      │         └─> XGBoost multi-class training (pure windows only)
      │
      └─> attacker-centric evaluation (held-out test windows only)
           ├─> simulate N users (user IDs via MAC remapping)
           ├─> for each user: build fixed blocks by mixing app windows
           │    - Bitcoin user: bitcoinsta + k background apps
           │    - Non-Bitcoin user: background apps only
           ├─> score each user by mean p(bitcoinsta) over blocks
           ├─> rank users (attacker view)
           └─> save metrics + plots + report under results/
```

Here **k = num background apps** (the number of concurrent non-Bitcoin application types mixed with Bitcoin for Bitcoin users).

## Outputs

After running the experiment runner, results are written to:

- `results/metrics.csv` (columns: `seed,N,MixingLevel,metric_name,value`)
- `results/figures/attacker_metrics_vs_num_background_apps.png`
- `results/report.md` (concise report + embedded figure)

## Experiment configuration

Edit `experiments/config_example.json` to control:

- **Scenario size**: `N_values`, `num_runs`, `seed_start`
- **Mixing**: `mixing_levels` (interpreted as “num background apps”)
- **User aggregation**: `user_agg_num_blocks`
- **Client simulation stability**:
  - `bitcoin_packet_fraction_in_block`
  - `btc_target_packets_per_block`
  - `min_component_packets`
- **Attacker decision rule**:
  - `decision_rule.type = "topm"` (rank users by score; predict top‑m suspects)
  - `decision_rule.min_m_pred` (minimum shortlist size)

## Repository structure (current)

```
wifi_btc_attack/
├── bitcoin_detector.py
├── experiments/
│   ├── __init__.py
│   ├── run.py
│   └── config_example.json
├── data/
│   ├── bitcoinsta.json
│   ├── download.json
│   ├── game.json
│   ├── music.json
│   ├── video.json
│   └── web.json
└── results/
    ├── metrics.csv
    ├── report.md
    └── figures/
        └── attacker_metrics_vs_num_background_apps.png
```

## Notes

- The experiment runner uses a leakage-safe split: per-class **time split** into train/test before windowing.
- `data_old/` contains legacy data and is not used by the current pipeline.

# Bitcoin traffic detection + attacker-centric victim identification

This repo contains a Wi‑Fi traffic analysis pipeline that:

- Trains a **per-window traffic classifier** using a fixed 50D feature extractor (sizes/timing/direction/MAC stats) and **XGBoost**.
- Runs an **attacker-centric evaluation** that simulates multi-user Wi‑Fi scenarios and ranks users by **Bitcoin likelihood** (`p(bitcoinsta)`), under increasing background-app mixing levels \(k=0..5\).

The core learning algorithm (feature extraction + XGBoost) is unchanged; the experiments focus on **Bitcoin detection and victim identification under mixed traffic**.

## Dataset format (current)

The dataset must be under `data/` as **flat JSON files**:

- Each `data/*.json` file is treated as a **distinct application class** (class id = filename stem).
- **Bitcoin class (currently)**: `bitcoinsta` (from `data/bitcoinsta.json`). At the moment, Bitcoin traffic in this dataset is **only** `bitcoinsta`.
- **Background classes (current `data/` snapshot)**:
  - `download` (`data/download.json`)
  - `game` (`data/game.json`)
  - `music` (`data/music.json`)
  - `video` (`data/video.json`)
  - `web` (`data/web.json`)

If you add more `data/*.json` files later, they will automatically become additional classes.

Each JSON file must be a list of packets with (at least) these fields:

- `ts` (float timestamp)
- `phy_len`, `mac_len`, `enc_payload_len` (ints)
- `sa`, `da`, `bssid` (MAC strings)
- `type`, `subtype` (ints)
- `protected`, `retry` (0/1)
- `direction` (`"tx"`/`"rx"`)
- `rssi` (int/float)

## Recommended environment (conda)

On macOS, some “framework Python” installs can segfault with NumPy/OpenBLAS. This repo is validated using conda.

```bash
conda create -n wifi_btc python=3.10 -y
conda activate wifi_btc
conda install -c conda-forge numpy pandas scikit-learn xgboost joblib matplotlib -y
```

## Quick start

### 1) Train + basic held-out mixture check (single script)

```bash
python -u bitcoin_detector.py
```

This trains a **multi-class** XGBoost model over `data/*.json` (pure windows) and runs a basic held-out mixture sweep. It also saves:

- `wifi_multiclass_model.pkl`

### 2) Attacker-centric “victim identification” experiment (recommended)

```bash
python -u -m experiments.run --config experiments/config_example.json
```

This simulates scenarios with:

- **N users** (configurable; e.g., N=5/10/20)
- **Num background apps (k)** = number of concurrent background app types mixed with Bitcoin for Bitcoin users (k=0..5)
- A subset of users running Bitcoin; others are non-Bitcoin-only

The attacker outputs a **per-user Bitcoin likelihood score**, ranks users, and reports user-level detection/ranking metrics.

## Outputs

After running the experiment runner, results are written to:

- `results/metrics.csv` (columns: `seed,N,MixingLevel,metric_name,value`)
- `results/figures/attacker_metrics_vs_num_background_apps.png`
- `results/report.md` (concise report + embedded figure)

## Experiment configuration

Edit `experiments/config_example.json` to control:

- **Scenario size**: `N_values`, `num_runs`, `seed_start`
- **Mixing**: `mixing_levels` (interpreted as “num background apps”)
- **User aggregation**: `user_agg_num_blocks`
- **Client simulation stability**:
  - `bitcoin_packet_fraction_in_block`
  - `btc_target_packets_per_block`
  - `min_component_packets`
- **Attacker decision rule**:
  - `decision_rule.type = "topm"` (rank users by score; predict top‑m suspects)
  - `decision_rule.min_m_pred` (minimum shortlist size)

## Repository structure (current)

```
wifi_btc_attack/
├── bitcoin_detector.py
├── experiments/
│   ├── __init__.py
│   ├── run.py
│   └── config_example.json
├── data/
│   ├── bitcoinsta.json
│   ├── download.json
│   ├── game.json
│   ├── music.json
│   ├── video.json
│   └── web.json
└── results/
    ├── metrics.csv
    ├── report.md
    └── figures/
        └── attacker_metrics_vs_num_background_apps.png
```

## Notes

- The experiment runner uses a leakage-safe split: per-class **time split** into train/test before windowing.
- `data_old/` contains legacy data and is not used by the current pipeline.

# Bitcoin Traffic Detector

A machine learning-based system for detecting Bitcoin network traffic in WiFi frame streams using XGBoost classification and sliding window segmentation.

## Overview

This project implements a Bitcoin traffic detector that can identify Bitcoin Initial Block Download (IBD) and Bitcoin Stable (STA) traffic patterns within WiFi packet streams, even when mixed with video and web traffic. The system uses statistical feature extraction and gradient boosting to achieve high detection accuracy.


## Implementation Details

### 1. Data Loading

- **Source Folders**: Only loads from 4 specific folders:
  - `bitcoinsta/` - Bitcoin Stable phase traffic
  - `video/` - Pure video streaming traffic
  - `web/` - Pure web browsing traffic
  ... and other background apps
- **Excluded**: All pre-mixed folders (e.g., `bitcoinibd_video/`, `bitcoinibd_web/`, etc.)
- **File Format**: JSON files containing arrays of WiFi packet records

### 2. Sliding Window Segmentation

The continuous WiFi frame stream is partitioned using fixed-duration sliding time windows:

- **Window Duration (W)**: 200ms (0.2 seconds)
- **Step Size (S)**: 100ms (0.1 seconds)
- **Minimum Frames**: 10 frames per window (windows with fewer frames are discarded)
- **Temporal Ordering**: All frames are sorted by timestamp (`ts`) before segmentation

**Algorithm**:
1. Sort all packets by timestamp
2. Starting from the first packet timestamp, create windows of duration W
3. Advance window by step size S
4. For each window, collect all packets where `start ≤ ts < start + W`
5. Discard windows with fewer than `min_frames` packets

### 3. Feature Extraction

Each window segment is converted into a 50-dimensional feature vector:

#### Packet Size Features (15 features)
- For `phy_len`, `mac_len`, `enc_payload_len`:
  - Mean, Standard Deviation, Min, Max, Median (5 features × 3 = 15)

#### Timing Features (3 features)
- Mean inter-packet interval
- Standard deviation of inter-packet intervals
- Packet rate (packets per second)

#### Direction Features (2 features)
- TX packet ratio
- RX packet ratio

#### Type/Subtype Distribution (9 features)
- Type distribution (4 types: 0, 1, 2, 3)
- Top 5 subtype frequencies

#### RSSI Features (5 features)
- Mean RSSI
- Standard deviation RSSI
- Min RSSI
- Max RSSI
- Median RSSI

#### MAC Address Features (3 features)
- Unique source address (SA) count
- Unique destination address (DA) count
- Unique BSSID count

#### Protocol Features (2 features)
- Protected packet ratio
- Retry packet ratio

#### Additional Statistical Features (11 features)
- Total packet count
- Size ratio (enc_payload_len / phy_len)
- Packet size percentiles (25th, 75th)
- Direction change frequency
- MAC address diversity ratios (SA, DA, BSSID)
- Encrypted payload size percentiles (25th, 75th)
- Coefficient of variation for packet sizes

### 4. Training Phase

- **Training Data**: 
  - Positive samples: Bitcoin IBD + STA segments (label=1)
  - Negative samples: Video + Web segments (label=0)
  - Balanced sampling to ensure equal representation
- **Model**: XGBoost Classifier
  - `n_estimators`: 100
  - `max_depth`: 6
  - `learning_rate`: 0.1
  - `eval_metric`: logloss
- **Train/Validation Split**: 80/20 with stratification
- **Model Persistence**: Saved as `bitcoin_detector_model.pkl`

### 5. Testing Phase

- **Test Data Creation**:
  - Mixed segments: Combine Bitcoin segments with video/web segments
  - Pure segments: Separate Bitcoin and non-Bitcoin segments
- **Balancing**: Ensures equal proportion of Bitcoin (1) and Non-Bitcoin (0) samples
- **Evaluation Metrics**:
  - Confusion Matrix
  - Classification Report (Precision, Recall, F1-score)
  - Accuracy
  - False Positive Rate (FPR)
  - Feature Importance

## Execution Results

### Data Processing Summary

```
[STEP 1] Data Loading:
  - Bitcoin IBD: 10 files loaded
  - Bitcoin STA: 4 files loaded
  - Video: 1 file loaded
  - Web: 1 file loaded

[STEP 2] Segmentation Results:
  - Bitcoin IBD segments: 33,982 windows
  - Bitcoin STA segments: 2,407 windows
  - Video segments: 717 windows
  - Web segments: 512 windows
  - Total Bitcoin segments: 36,389
  - Total Non-Bitcoin segments: 1,229
```

### Training Results

```
Training Data:
  - Total training samples: 37,618
  - Features per sample: 50
  - Label distribution:
    - Bitcoin (1): 36,389 samples
    - Non-Bitcoin (0): 1,229 samples
  
Train/Validation Split:
  - Training set: 30,094 samples
  - Validation set: 7,524 samples
```

### Test Results

```
Test Data:
  - Mixed test samples created: 2,458
  - Balanced test set: 4,916 samples
    - Bitcoin samples: 2,458
    - Non-Bitcoin samples: 2,458

Performance Metrics:
  - Accuracy: 91.27%
  - Precision: 0.9660
  - Recall: 0.8556
  - F1-Score: 0.9073
  - False Positive Rate (FPR): 0.0301 (3.01%)
  
Confusion Matrix:
                Predicted
              Non-Bitcoin  Bitcoin
  Actual
  Non-Bitcoin     2384       74
  Bitcoin          355      2103

Confusion Matrix Breakdown:
  - True Negatives (TN): 2384
  - False Positives (FP): 74
  - False Negatives (FN): 355
  - True Positives (TP): 2103

Classification Report:
              precision    recall  f1-score   support
  Non-Bitcoin     0.87      0.97      0.92      2458
     Bitcoin       0.97      0.86      0.91      2458
```

### Feature Importance (Top 10)

The most important features for Bitcoin detection:

1. **Feature 2** (0.3922) - Likely related to packet size statistics
2. **Feature 38** (0.1667) - MAC address or diversity feature
3. **Feature 4** (0.0990) - Packet size feature
4. **Feature 0** (0.0398) - Packet size mean
5. **Feature 1** (0.0361) - Packet size std
6. **Feature 3** (0.0301) - Packet size min
7. **Feature 44** (0.0286) - Additional statistical feature
8. **Feature 46** (0.0240) - Additional statistical feature
9. **Feature 39** (0.0225) - MAC address feature
10. **Feature 49** (0.0186) - Additional statistical feature

### Performance Analysis

- **High Precision (0.97)**: When the model predicts Bitcoin, it's correct 97% of the time
- **High Recall for Non-Bitcoin (0.97)**: Correctly identifies 97% of non-Bitcoin traffic
- **Good Recall for Bitcoin (0.86)**: Identifies 86% of Bitcoin traffic
- **Balanced Performance**: F1-scores of 0.92 and 0.91 indicate well-balanced precision and recall
- **Low False Positive Rate (3.01%)**: Only 3.01% of non-Bitcoin traffic is incorrectly classified as Bitcoin

The model demonstrates strong capability to:
1. Distinguish Bitcoin traffic from video/web traffic
2. Detect Bitcoin patterns even in mixed traffic scenarios
3. Maintain low false positive rate (FPR = 3.01%, only 74 out of 2458 non-Bitcoin samples misclassified as Bitcoin)
4. High precision ensures minimal false alarms when detecting Bitcoin traffic

## File Structure

```
wifi_btc_attack/
├── bitcoin_detector.py          # Main detector implementation
├── bitcoin_detector_model.pkl   # Trained XGBoost model
├── README.md                    # This file
└── data/                        # Data directory
    ├── bitcoinibd/              # Bitcoin IBD data (10 files)
    ├── bitcoinsta/              # Bitcoin STA data (4 files)
    ├── video/                   # Video data (1 file)
    └── web/                     # Web data (1 file)
```

## Dependencies

- Python 3.9+
- numpy >= 1.20.1
- pandas >= 1.2.4
- scikit-learn
- xgboost >= 2.1.4
- joblib

## Usage

### Basic Execution

```bash
# Using conda Python (recommended)
/opt/anaconda3/bin/python bitcoin_detector.py

# Or with unbuffered output for real-time progress
/opt/anaconda3/bin/python -u bitcoin_detector.py
```

### Execution Flow

The script executes in 13 sequential steps:

1. **Data Loading**: Loads JSON files from allowed folders only
2. **Segmentation**: Partitions packets into sliding time windows
3. **Segmentation Summary**: Reports segment counts by type
4. **Feature Extraction (Training)**: Extracts features from training segments
5. **Training Data Preparation**: Prepares and balances training dataset
6. **Train/Validation Split**: Splits data for model training
7. **Model Training**: Trains XGBoost classifier
8. **Model Saving**: Persists trained model to disk
9. **Mixed Test Creation**: Creates mixed segments for testing
10. **Test Balancing**: Balances test dataset
11. **Feature Extraction (Test)**: Extracts features from test samples
12. **Inference**: Runs predictions on test set
13. **Evaluation**: Computes and displays performance metrics

### Progress Monitoring

The implementation includes detailed progress printing:
- File-by-file processing status
- Segment counting (every file)
- Feature extraction progress (every 1000 samples)
- Step-by-step execution status
- Final evaluation results

## Key Design Decisions

1. **Sliding Window Approach**: Enables multiple training samples from each file, capturing temporal patterns
2. **Statistical Features**: 50-dimensional feature vector captures packet size, timing, direction, and protocol characteristics
3. **Binary Classification**: Simple and effective for Bitcoin vs. Non-Bitcoin detection
4. **Balanced Datasets**: Ensures fair evaluation and prevents class imbalance issues
5. **Pure Folder Usage**: Only uses clean data sources, avoiding pre-mixed data for training
6. **Mixed Test Scenarios**: Tests model's ability to detect Bitcoin in realistic mixed traffic

## Limitations and Future Work

### Current Limitations

1. **Class Imbalance**: Training data has significantly more Bitcoin samples (36,389) than non-Bitcoin (1,229)
2. **Fixed Window Size**: 200ms windows may not be optimal for all traffic patterns
3. **Feature Engineering**: Current features are hand-crafted; learned features might improve performance
4. **Mixed Traffic Handling**: Simple packet merging may not reflect real-world mixing patterns

### Potential Improvements

1. **Data Augmentation**: Generate more balanced training data through synthetic mixing
2. **Hyperparameter Tuning**: Optimize XGBoost parameters using grid search or Bayesian optimization
3. **Deep Learning**: Explore neural networks for automatic feature learning
4. **Real-time Detection**: Implement streaming detection for live traffic analysis
5. **Multi-class Classification**: Extend to distinguish between IBD, STA, video, and web separately
6. **Cross-validation**: Implement k-fold cross-validation for more robust evaluation

## Technical Notes

### Segmentation Algorithm

The sliding window algorithm ensures:
- **Temporal Continuity**: Windows are created in chronological order
- **Overlap**: 50% overlap (100ms step, 200ms window) captures patterns at boundaries
- **Quality Control**: Minimum frame threshold filters out low-activity windows

### Feature Engineering Rationale

- **Packet Sizes**: Bitcoin traffic has characteristic packet size distributions
- **Timing Patterns**: Inter-packet intervals reveal traffic patterns
- **Direction Ratios**: TX/RX ratios differ between Bitcoin and web/video traffic
- **MAC Diversity**: Bitcoin connections show different MAC address patterns
- **Protocol Features**: Protected/retry ratios indicate encryption and reliability patterns

## Citation

If you use this implementation in your research, please cite:

```
Bitcoin Traffic Detector
WiFi Frame Analysis using XGBoost Classification
Implementation with Sliding Window Segmentation
```

## License

This project is provided as-is for research and educational purposes.

## Contact

For questions or issues, please refer to the implementation code and documentation.

---

**Last Updated**: Based on execution results from December 27, 2025
**Model Version**: XGBoost 2.1.4
**Python Version**: 3.9.6 (Conda)

