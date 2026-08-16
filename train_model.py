import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.expanduser("~/sdn_ddos_project")

LOCAL_CSV = os.path.join(
    BASE_DIR,
    "dataset",
    "network_telemetry.csv"
)

MODEL_SAVE_PATH = os.path.join(
    BASE_DIR,
    "model.pkl"
)

# EXACT features used by the Ryu controller
FEATURE_COLS = [
    "packet_count",
    "byte_count",
    "duration_sec",
    "pkt_rate",
    "byte_rate",
    "avg_pkt_size"
]

# Minimum valid interval
MIN_INTERVAL_SEC = 0.01

# Prevent impossible packet sizes from entering training
MAX_SANE_AVG_PKT_SIZE = 1600.0


# ============================================================
# LABEL MAPPING
# ============================================================

def map_label(label):
    """
    Label mapping:

        0 = Normal
        1 = Other-Malicious
        2 = DDoS-Flood
    """

    text = str(label).strip().upper()

    # Normal
    if text in {
        "0",
        "NORMAL",
        "BENIGN"
    }:
        return 0

    # DDoS
    if text in {
        "2",
        "DDOS",
        "DDOS-FLOOD",
        "DDOS FLOOD",
        "FLOOD",
        "SYN-FLOOD",
        "SYN FLOOD",
        "SYNFLOOD",
        "UDP-FLOOD",
        "UDP FLOOD",
        "UDPFLOOD",
        "ICMP-FLOOD",
        "ICMP FLOOD",
        "ICMPFLOOD",
        "HTTP-FLOOD",
        "HTTP FLOOD",
        "HTTPFLOOD"
    }:
        return 2

    # Everything else malicious
    return 1


# ============================================================
# LOAD LOCAL MININET DATA
# ============================================================

def load_local_data():

    print("\n==============================================")
    print("       LOADING MININET TELEMETRY")
    print("==============================================")

    if not os.path.exists(LOCAL_CSV):

        raise FileNotFoundError(
            f"\n❌ Telemetry file not found:\n{LOCAL_CSV}\n"
        )

    print(f"\n📡 Reading:")
    print(LOCAL_CSV)

    raw = pd.read_csv(
        LOCAL_CSV,
        low_memory=False
    )

    # Normalize column names
    raw.columns = (
        raw.columns
        .str.strip()
        .str.lower()
    )

    print("\nColumns found:")
    print(raw.columns.tolist())

    # --------------------------------------------------------
    # Required columns
    # --------------------------------------------------------

    required = {
        "timestamp",
        "datapath_id",
        "eth_src",
        "eth_dst",
        "in_port",
        "packet_count",
        "byte_count",
        "label"
    }

    missing = required - set(raw.columns)

    if missing:

        raise RuntimeError(
            "\n❌ Missing required columns:\n"
            + "\n".join(sorted(missing))
        )

    # --------------------------------------------------------
    # Convert numeric columns
    # --------------------------------------------------------

    numeric_cols = [
        "timestamp",
        "datapath_id",
        "in_port",
        "packet_count",
        "byte_count"
    ]

    for col in numeric_cols:

        raw[col] = pd.to_numeric(
            raw[col],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Convert labels
    # --------------------------------------------------------

    raw["label"] = raw["label"].apply(map_label)

    # --------------------------------------------------------
    # Remove invalid rows
    # --------------------------------------------------------

    before = len(raw)

    raw = raw.dropna(
        subset=[
            "timestamp",
            "datapath_id",
            "in_port",
            "packet_count",
            "byte_count",
            "label"
        ]
    ).copy()

    print(
        f"\n🧹 Removed "
        f"{before - len(raw):,} invalid rows."
    )

    if raw.empty:

        raise RuntimeError(
            "❌ No valid telemetry rows remain."
        )

    # ========================================================
    # SORT SNAPSHOTS
    # ========================================================

    print("\n⏱️ Sorting telemetry chronologically...")

    key_cols = [
        "datapath_id",
        "eth_src",
        "eth_dst",
        "in_port"
    ]

    raw = raw.sort_values(
        key_cols + ["timestamp"]
    ).copy()

    # ========================================================
    # GROUP BY FLOW
    # ========================================================

    grouped = raw.groupby(
        key_cols,
        sort=False
    )

    # ========================================================
    # CONVERT CUMULATIVE COUNTERS
    # INTO INTERVAL DELTAS
    # ========================================================

    print(
        "\n🔄 Converting cumulative OpenFlow "
        "counters into delta windows..."
    )

    raw["packet_count"] = (
        grouped["packet_count"]
        .diff()
    )

    raw["byte_count"] = (
        grouped["byte_count"]
        .diff()
    )

    raw["duration_sec"] = (
        grouped["timestamp"]
        .diff()
    )

    # ========================================================
    # REMOVE FIRST SNAPSHOT
    # ========================================================

    raw = raw.dropna(
        subset=[
            "packet_count",
            "byte_count",
            "duration_sec"
        ]
    ).copy()

    # ========================================================
    # REMOVE COUNTER RESETS / INVALID WINDOWS
    # ========================================================

    raw = raw[
        (raw["packet_count"] >= 0) &
        (raw["byte_count"] >= 0) &
        (raw["duration_sec"] > 0)
    ].copy()

    # ========================================================
    # REMOVE EXTREMELY SMALL WINDOWS
    # ========================================================

    raw = raw[
        raw["duration_sec"] >= MIN_INTERVAL_SEC
    ].copy()

    print(
        f"\n✅ Delta windows created: "
        f"{len(raw):,}"
    )

    return raw


# ============================================================
# FEATURE ENGINEERING
# ============================================================

def build_features(df):

    print("\n==============================================")
    print("          FEATURE ENGINEERING")
    print("==============================================")

    df = df.copy()

    # --------------------------------------------------------
    # Remove infinity / NaN
    # --------------------------------------------------------

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.dropna(
        subset=[
            "packet_count",
            "byte_count",
            "duration_sec",
            "label"
        ],
        inplace=True
    )

    # --------------------------------------------------------
    # Safety limits
    # --------------------------------------------------------

    df["duration_sec"] = df[
        "duration_sec"
    ].clip(lower=1e-6)

    df["packet_count"] = df[
        "packet_count"
    ].clip(lower=0)

    df["byte_count"] = df[
        "byte_count"
    ].clip(lower=0)

    # ========================================================
    # CALCULATE FEATURES
    # ========================================================

    # Packets per second
    df["pkt_rate"] = (
        df["packet_count"]
        / df["duration_sec"]
    )

    # Bytes per second
    df["byte_rate"] = (
        df["byte_count"]
        / df["duration_sec"]
    )

    # Average packet size
    df["avg_pkt_size"] = (
        df["byte_count"]
        /
        df["packet_count"].clip(lower=1)
    )

    # ========================================================
    # REMOVE IMPOSSIBLE PACKET SIZES
    # ========================================================

    before = len(df)

    df = df[
        df["avg_pkt_size"]
        <= MAX_SANE_AVG_PKT_SIZE
    ].copy()

    print(
        f"🧹 Removed "
        f"{before - len(df):,} invalid "
        f"average-packet-size rows."
    )

    # ========================================================
    # FINAL CLEANUP
    # ========================================================

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.dropna(
        subset=FEATURE_COLS + ["label"],
        inplace=True
    )

    return df


# ============================================================
# PRINT DATASET SUMMARY
# ============================================================

def print_dataset_summary(df):

    print("\n==============================================")
    print("             DATASET SUMMARY")
    print("==============================================")

    print(
        f"\nTotal training windows: "
        f"{len(df):,}"
    )

    print("\nClass distribution:")

    counts = (
        df["label"]
        .value_counts()
        .sort_index()
    )

    names = {
        0: "Normal",
        1: "Other-Malicious",
        2: "DDoS-Flood"
    }

    for label, count in counts.items():

        print(
            f"  {label} = "
            f"{names.get(label, 'Unknown'):18s} "
            f"{count:,}"
        )

    print("\nFeature ranges:")

    for feature in FEATURE_COLS:

        print(
            f"  {feature:18s} "
            f"min={df[feature].min():.2f} "
            f"max={df[feature].max():.2f}"
        )


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(df):

    print("\n==============================================")
    print("          TRAINING RANDOM FOREST")
    print("==============================================")

    X = df[FEATURE_COLS].copy()

    y = df["label"].astype(int)

    # --------------------------------------------------------
    # Check number of classes
    # --------------------------------------------------------

    unique_classes = sorted(
        y.unique().tolist()
    )

    print(
        f"\nClasses present: "
        f"{unique_classes}"
    )

    if len(unique_classes) < 2:

        raise RuntimeError(
            "\n❌ Training requires at least TWO classes.\n"
            "Collect both Normal and DDoS traffic first."
        )

    # --------------------------------------------------------
    # Split data
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    print(
        f"\nTraining samples: "
        f"{len(X_train):,}"
    )

    print(
        f"Testing samples: "
        f"{len(X_test):,}"
    )

    # ========================================================
    # RANDOM FOREST
    # ========================================================

    model = RandomForestClassifier(

        n_estimators=300,

        max_depth=14,

        min_samples_leaf=2,

        class_weight="balanced",

        random_state=42,

        n_jobs=-1
    )

    print("\n🌲 Training model...")

    model.fit(
        X_train,
        y_train
    )

    print("✅ Training complete.")

    # ========================================================
    # EVALUATION
    # ========================================================

    print("\n==============================================")
    print("             MODEL EVALUATION")
    print("==============================================")

    predictions = model.predict(
        X_test
    )

    # Only include classes actually present
    target_names_map = {
        0: "Normal",
        1: "Other-Malicious",
        2: "DDoS-Flood"
    }

    labels = sorted(
        np.unique(y)
    )

    target_names = [
        target_names_map[label]
        for label in labels
    ]

    print("\nClassification Report:\n")

    print(
        classification_report(
            y_test,
            predictions,
            labels=labels,
            target_names=target_names,
            zero_division=0
        )
    )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=labels
        )
    )

    # ========================================================
    # FEATURE IMPORTANCE
    # ========================================================

    print("\n==============================================")
    print("           FEATURE IMPORTANCE")
    print("==============================================")

    importance = sorted(
        zip(
            FEATURE_COLS,
            model.feature_importances_
        ),
        key=lambda item: item[1],
        reverse=True
    )

    for name, value in importance:

        print(
            f"{name:20s} "
            f"{value:.4f}"
        )

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    classes = {}

    for class_id in model.classes_:

        class_id = int(class_id)

        if class_id == 0:
            classes[class_id] = "Normal"

        elif class_id == 1:
            classes[class_id] = "Other-Malicious"

        elif class_id == 2:
            classes[class_id] = "DDoS-Flood"

    model_bundle = {

        # Actual Random Forest
        "model": model,

        # Exact controller feature order
        "feature_cols": FEATURE_COLS,

        # Human-readable class names
        "classes": classes,

        # Important: controller must use delta windows
        "feature_mode": "interval_delta",

        # Window type
        "window_type": "5_second_delta",

        # Model source
        "training_source": "Mininet_OpenFlow_telemetry"
    }

    joblib.dump(
        model_bundle,
        MODEL_SAVE_PATH
    )

    print("\n==============================================")
    print("             MODEL SAVED")
    print("==============================================")

    print(
        f"\n✅ Model saved to:\n"
        f"{MODEL_SAVE_PATH}"
    )

    print("\nModel classes:")

    for class_id, name in classes.items():

        print(
            f"  {class_id} = {name}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("==============================================")
    print("     SDN DDoS ML MODEL TRAINING")
    print("          DELTA WINDOW MODE")
    print("==============================================")

    # --------------------------------------------------------
    # 1. Load Mininet telemetry
    # --------------------------------------------------------

    df = load_local_data()

    # --------------------------------------------------------
    # 2. Build delta-window features
    # --------------------------------------------------------

    df = build_features(df)

    if df.empty:

        raise RuntimeError(
            "\n❌ No usable training data remains."
        )

    # --------------------------------------------------------
    # 3. Dataset summary
    # --------------------------------------------------------

    print_dataset_summary(df)

    # --------------------------------------------------------
    # 4. Train
    # --------------------------------------------------------

    model = train_model(df)

    # --------------------------------------------------------
    # 5. Save
    # --------------------------------------------------------

    save_model(model)

    print("\n==============================================")
    print("        🎉 TRAINING COMPLETE")
    print("==============================================")

    print(
        "\nThe model is now trained using:"
    )

    print(
        "  Mininet telemetry"
    )

    print(
        "  ↓"
    )

    print(
        "  OpenFlow counter deltas"
    )

    print(
        "  ↓"
    )

    print(
        "  5-second windows"
    )

    print(
        "  ↓"
    )

    print(
        "  packet_count"
    )

    print(
        "  byte_count"
    )

    print(
        "  duration_sec"
    )

    print(
        "  pkt_rate"
    )

    print(
        "  byte_rate"
    )

    print(
        "  avg_pkt_size"
    )

    print(
        "  ↓"
    )

    print(
        "  Random Forest"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()