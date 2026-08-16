import csv
import json
import os
import time
import joblib
import pandas as pd

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4


# ============================================================
# CONFIGURATION
# ============================================================

MODE = os.environ.get("SDN_MODE", "collect").strip().lower()

# The protected host. Only traffic aimed AT this host is analysed, and
# this host is never blocked. Defaults to h2 (10.0.0.2). Override with
# SDN_VICTIM_IP if the topology changes.
VICTIM_IP = os.environ.get("SDN_VICTIM_IP", "10.0.0.2").strip()

# Used only in collection mode.
# 0 = Normal
# 1 = Other-Malicious
# 2 = DDoS-Flood
LABEL = int(os.environ.get("SDN_LABEL", "0"))

BASE_DIR = os.path.expanduser("~/sdn_ddos_project")
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

TELEMETRY_PATH = os.path.join(DATASET_DIR, "network_telemetry.csv")
PREDICTIONS_PATH = os.path.join(DATASET_DIR, "live_predictions.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

# Dashboard integration (additive - does not affect detection).
# The controller writes a live JSON snapshot of what it already computed
# so the web dashboard can display REAL experiment data, and optionally
# reads live threshold overrides set from the dashboard UI.
DASHBOARD_STATE_FILE = os.path.join(BASE_DIR, "dashboard_state.json")
DASHBOARD_CONTROL_FILE = os.path.join(BASE_DIR, "dashboard_control.json")
DASHBOARD_HISTORY_LEN = 60
DASHBOARD_EVENTS_LEN = 40

# The training script creates interval/delta windows from OpenFlow
# cumulative counters. Keep the controller polling at 5 seconds so
# the live features have the same meaning as the training data.
POLL_INTERVAL = 5.0

FEATURE_COLS = [
    "packet_count",
    "byte_count",
    "duration_sec",
    "pkt_rate",
    "byte_rate",
    "avg_pkt_size",
]

CLASS_NAMES = {
    0: "NORMAL",
    1: "OTHER-MALICIOUS",
    2: "DDOS-FLOOD",
}

MAX_SANE_AVG_PKT_SIZE = 1600.0
MIN_INTERVAL_SEC = 0.5

# Keep False until detection is verified.
AUTO_MITIGATE = True

# ============================================================
# AGGREGATE (DISTRIBUTED) DDoS DETECTION
# ============================================================
#
# Per-source detection (the ML model) answers: "is THIS one host
# flooding?". That misses a distributed attack where each host stays
# individually modest but the COMBINED traffic toward the victim is
# high. Aggregate detection sums the 5-second delta rates of every
# source heading to the victim.
#
# EXACT CONDITION for a DISTRIBUTED-DDoS window (enforced in
# evaluate_and_mitigate) - BOTH must hold:
#   (1) at least 2 DISTINCT sources are each flooding the victim at
#       >= CONTRIBUTOR_PKT_RATE_THRESHOLD pkt/s, AND
#   (2) the combined victim-bound rate crosses the aggregate threshold:
#           agg_pkt_rate  >= AGG_PKT_RATE_THRESHOLD
#             OR  agg_byte_rate >= AGG_BYTE_RATE_THRESHOLD
#
# A single flooding source satisfies (2) but never (1), so it stays a
# single-source DoS handled by the per-source ML path - it is never
# relabelled DDoS.
#
# Values are sized for THIS Mininet topology, where a "moderate"
# attacker is generated with fixed-interval ping (e.g. ping -i 0.005 =
# ~200 pkt/s). Three such attackers total ~600 pkt/s, comfortably over
# AGG_PKT_RATE_THRESHOLD, while each easily clears the contributor bar.
# Normal ping is ~1 pkt/s per host, so even 3-4 normal hosts total only
# single-digit pkt/s - far below both bars, and 0 contributors. Override
# any value from the environment if your rates differ.
AGG_PKT_RATE_THRESHOLD = float(
    os.environ.get("SDN_AGG_PKT_RATE", "300.0")
)
AGG_BYTE_RATE_THRESHOLD = float(
    os.environ.get("SDN_AGG_BYTE_RATE", "300000.0")
)

# A source counts as an attacking "contributor" only if its own rate
# toward the victim is at least this. Set well above normal ping
# (~1 pkt/s) but well below a moderate attacker (~200 pkt/s), so real
# flooders count and an occasional legitimate packet does not.
CONTRIBUTOR_PKT_RATE_THRESHOLD = float(
    os.environ.get("SDN_CONTRIBUTOR_PKT_RATE", "50.0")
)


class DDoSController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # =========================================================
    # INITIALIZATION
    # =========================================================

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}

        # Learned MAC -> IP, so we can tell the attacker from the victim.
        # Populated from ARP / IPv4 packets seen at the controller.
        self.mac_to_ip = {}

        # Previous cumulative OpenFlow counters.
        # key = (dpid, src, dst, in_port)
        # value = (packet_count, byte_count, timestamp)
        self.previous_stats = {}

        self.blocked_macs = set()

        # Consecutive DDOS-FLOOD (class 2) windows seen per source MAC.
        # key = eth_src, value = number of back-to-back flood windows.
        # Reset to 0 whenever a NORMAL/OTHER window is seen for that src.
        self.attack_counts = {}

        # Install a DROP rule only after this many consecutive flood
        # windows. With POLL_INTERVAL = 5s, a value of 2 means ~10s of
        # sustained flooding before automatic mitigation. Set to 1 to
        # block on the very first detection.
        self.ATTACK_THRESHOLD = 2

        # Consecutive windows in which the AGGREGATE (all-sources ->
        # victim) traffic crossed the DDoS threshold. Same 2-window
        # confirmation as per-source, tracked separately.
        self.aggregate_attack_count = 0

        # ---- Dashboard integration state (additive) ----
        # Live-adjustable copies of the detection thresholds. They start
        # at the configured defaults and may be overridden at runtime from
        # the dashboard UI (via DASHBOARD_CONTROL_FILE). The detection
        # ALGORITHM is unchanged - only these numeric limits can move.
        self.agg_pkt_limit = AGG_PKT_RATE_THRESHOLD
        self.agg_byte_limit = AGG_BYTE_RATE_THRESHOLD

        # Live-selectable protected victim. Defaults to the configured
        # VICTIM_IP; the dashboard may override it via the control file.
        # Detection behaviour is identical unless an override is provided.
        self.victim_ip = VICTIM_IP

        # Per-poll ML result per source, rolling event log, rolling rate
        # history for the chart, and the latest human-readable status.
        self.last_predictions = {}
        self.dashboard_events = []
        self.history = []
        self.detection_status = "NORMAL"
        self.victim_cumulative_packets = 0
        self.victim_cumulative_bytes = 0

        self.model = None
        self.feature_cols = list(FEATURE_COLS)
        self.model_classes = []
        self.model_class_names = {}
        self.model_bundle = {}

        os.makedirs(DATASET_DIR, exist_ok=True)

        if MODE not in ("collect", "detect"):
            raise ValueError("SDN_MODE must be collect or detect")

        # ----------------------------------------------------
        # COLLECTION MODE
        # ----------------------------------------------------
        if MODE == "collect":
            if LABEL not in (0, 1, 2):
                raise ValueError("SDN_LABEL must be 0, 1 or 2")

            self.initialize_telemetry_csv()

            self.logger.info("")
            self.logger.info("==========================================")
            self.logger.info("SDN DDoS CONTROLLER")
            self.logger.info("COLLECTION MODE")
            self.logger.info("==========================================")
            self.logger.info(
                "LABEL = %d (%s)",
                LABEL,
                CLASS_NAMES[LABEL],
            )
            self.logger.info("Writing telemetry to: %s", TELEMETRY_PATH)

        # ----------------------------------------------------
        # DETECTION MODE
        # ----------------------------------------------------
        else:
            self.load_model()
            self.initialize_prediction_csv()

            self.logger.info("")
            self.logger.info("==========================================")
            self.logger.info("SDN DDoS CONTROLLER")
            self.logger.info("DETECTION MODE")
            self.logger.info("==========================================")
            self.logger.info("Model classes: %s", self.model_classes)
            self.logger.info(
                "Class names: %s",
                self.model_class_names,
            )
            self.logger.info("Feature mode: %s", self.model_bundle.get("feature_mode", "unknown"))
            self.logger.info("Window type: %s", self.model_bundle.get("window_type", "unknown"))
            self.logger.info("Victim (protected): %s", VICTIM_IP)
            self.logger.info(
                "Aggregate DDoS trigger: agg_pkt_rate >= %.0f pkt/s OR agg_byte_rate >= %.0f byte/s",
                AGG_PKT_RATE_THRESHOLD,
                AGG_BYTE_RATE_THRESHOLD,
            )
            self.logger.info(
                "Confirmation: %d consecutive windows (per-source AND aggregate)",
                self.ATTACK_THRESHOLD,
            )

        self.monitor_thread = hub.spawn(self.monitor)

    # =========================================================
    # TELEMETRY CSV
    # =========================================================

    def initialize_telemetry_csv(self):
        if not os.path.exists(TELEMETRY_PATH):
            with open(TELEMETRY_PATH, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "datapath_id",
                    "eth_src",
                    "eth_dst",
                    "in_port",
                    "packet_count",
                    "byte_count",
                    "duration_sec",
                    "label",
                ])

            self.logger.info("Created new telemetry CSV")

    # =========================================================
    # PREDICTION CSV
    # =========================================================

    def initialize_prediction_csv(self):
        if not os.path.exists(PREDICTIONS_PATH):
            with open(PREDICTIONS_PATH, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "datapath_id",
                    "eth_src",
                    "eth_dst",
                    "in_port",
                    "packet_count",
                    "byte_count",
                    "duration_sec",
                    "pkt_rate",
                    "byte_rate",
                    "avg_pkt_size",
                    "prediction",
                    "prediction_name",
                ])

    # =========================================================
    # LOAD MODEL
    # =========================================================

    def load_model(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"model.pkl not found:\n{MODEL_PATH}"
            )

        bundle = joblib.load(MODEL_PATH)

        if isinstance(bundle, dict):
            self.model_bundle = bundle
            self.model = bundle.get("model")
            self.feature_cols = list(
                bundle.get("feature_cols", FEATURE_COLS)
            )
            saved_classes = bundle.get("classes", {})
        else:
            # Backward compatibility with a plain sklearn model.pkl.
            self.model_bundle = {}
            self.model = bundle
            self.feature_cols = list(FEATURE_COLS)
            saved_classes = {}

        if self.model is None:
            raise RuntimeError("model.pkl does not contain a valid 'model'.")

        # The model's classes_ is the authoritative source for the
        # positions returned by predict_proba(). DO NOT assume that
        # probability index 0/1/2 corresponds to labels 0/1/2.
        if hasattr(self.model, "classes_"):
            self.model_classes = [int(x) for x in self.model.classes_]
        else:
            self.model_classes = sorted(
                int(x) for x in saved_classes.keys()
            )

        # Human-readable names from the model bundle, with safe fallback.
        for class_id in self.model_classes:
            if str(class_id) in saved_classes:
                self.model_class_names[class_id] = saved_classes[str(class_id)]
            elif class_id in saved_classes:
                self.model_class_names[class_id] = saved_classes[class_id]
            else:
                self.model_class_names[class_id] = CLASS_NAMES.get(
                    class_id,
                    f"CLASS-{class_id}",
                )

        # The uploaded training script uses exactly these six features.
        if self.feature_cols != FEATURE_COLS:
            raise RuntimeError(
                "Model feature order does not match the controller.\n"
                f"Model:      {self.feature_cols}\n"
                f"Controller: {FEATURE_COLS}"
            )

        self.logger.info("ML model loaded successfully.")
        self.logger.info("Features: %s", self.feature_cols)
        self.logger.info("Model classes_: %s", self.model_classes)

    # =========================================================
    # SWITCH FEATURES
    # =========================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info("Switch connected: DPID=%s", datapath.id)

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Table miss -> send unknown packets to controller.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(datapath, 0, match, actions)

    # =========================================================
    # ADD FLOW
    # =========================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
    ):
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        datapath.send_msg(mod)

    # =========================================================
    # MONITOR
    # =========================================================

    def monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                self.request_stats(datapath)

            hub.sleep(POLL_INTERVAL)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        request = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(request)

    # =========================================================
    # FLOW STATISTICS
    # =========================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        now = time.time()

        # ----- Aggregate accumulators for this poll -----
        # Combined rate of ALL sources heading toward the victim, plus a
        # per-source breakdown so we know who to block if the aggregate
        # crosses the DDoS threshold. Built up inside the loop below and
        # evaluated once, after every flow has been processed.
        agg_pkt_rate = 0.0
        agg_byte_rate = 0.0
        contributions = {}  # src_mac -> {pkt_rate, byte_rate, packets, bytes}

        # Dashboard: pick up any live threshold overrides from the UI and
        # start a fresh per-poll ML capture. Guarded so it can never break
        # detection.
        if MODE == "detect":
            self._refresh_dashboard_control()
            self.last_predictions = {}

        for stat in ev.msg.body:
            # Ignore table-miss entry.
            if stat.priority == 0:
                continue

            match = stat.match

            src = match.get("eth_src")
            dst = match.get("eth_dst")
            in_port = match.get("in_port")

            if src is None or dst is None or in_port is None:
                continue

            try:
                in_port = int(in_port)
                packet_count = int(stat.packet_count)
                byte_count = int(stat.byte_count)
            except (TypeError, ValueError):
                continue

            # This is the cumulative lifetime of the OpenFlow rule.
            # It is used only in collection mode for compatibility with
            # the training CSV. Detection mode uses the timestamp delta.
            flow_duration = (
                float(stat.duration_sec)
                + float(stat.duration_nsec) / 1_000_000_000.0
            )

            if flow_duration <= 0:
                continue

            key = (dpid, src, dst, in_port)

            # =====================================================
            # COLLECTION
            # =====================================================
            if MODE == "collect":
                self.write_telemetry(
                    now,
                    dpid,
                    src,
                    dst,
                    in_port,
                    packet_count,
                    byte_count,
                    flow_duration,
                )
                continue

            # =====================================================
            # DETECTION
            # =====================================================

            # Never re-process a source we have already blocked. This
            # stops the attack counter from climbing past the threshold
            # (1/2 -> 2/2 -> 3/2 ...) and stops repeat block attempts
            # once the DROP rule is in place.
            if src in self.blocked_macs:
                continue

            # Direction guard. With ping -f the victim's ICMP echo-replies
            # are just as fast as the attacker's requests, so the reverse
            # flow (h2 -> h1) also looks like a flood and the victim ends
            # up blocked. Resolve MAC -> IP and only inspect the attack
            # direction: traffic aimed at the victim, never traffic that
            # ORIGINATES from the victim.
            src_ip = self.mac_to_ip.get(src)
            dst_ip = self.mac_to_ip.get(dst)

            if self.victim_ip:
                # Never analyse (and therefore never blame) the victim.
                if src_ip == self.victim_ip:
                    continue
                # Only inspect flows heading to the victim. If the
                # destination IP is not yet learned, fall through and
                # let it be analysed rather than miss a real attack.
                if dst_ip is not None and dst_ip != self.victim_ip:
                    continue

            previous = self.previous_stats.get(key)

            if previous is None:
                # First observation establishes the baseline.
                self.previous_stats[key] = (
                    packet_count,
                    byte_count,
                    now,
                )
                continue

            old_packets, old_bytes, old_time = previous

            delta_packets = packet_count - old_packets
            delta_bytes = byte_count - old_bytes
            delta_time = now - old_time

            # Always update baseline, including after counter resets.
            self.previous_stats[key] = (
                packet_count,
                byte_count,
                now,
            )

            # Counter reset / flow replacement.
            if delta_packets < 0 or delta_bytes < 0:
                continue

            # Ignore empty windows.
            if delta_packets <= 0:
                continue

            # Ignore unrealistically short reply intervals.
            if delta_time < MIN_INTERVAL_SEC:
                continue

            # ----- Per-source rates (same delta window) -----
            # These feed BOTH the per-source ML path (via detect_flow)
            # and the aggregate accumulator. Every flow reaching this
            # point has already passed the direction guard, so it is
            # victim-bound traffic from a non-victim, non-blocked source.
            src_pkt_rate = delta_packets / delta_time
            src_byte_rate = delta_bytes / delta_time

            # Only fold CONFIRMED victim-bound traffic into the aggregate
            # (dst IP == the protected victim). This keeps the aggregate
            # detector strictly "traffic TO the victim" and never counts
            # the victim as a source. The per-source ML path below is
            # left untouched.
            if (not self.victim_ip) or (dst_ip == self.victim_ip):
                agg_pkt_rate += src_pkt_rate
                agg_byte_rate += src_byte_rate

                entry = contributions.setdefault(
                    src,
                    {"pkt_rate": 0.0, "byte_rate": 0.0,
                     "packets": 0, "bytes": 0},
                )
                entry["pkt_rate"] += src_pkt_rate
                entry["byte_rate"] += src_byte_rate
                entry["packets"] += delta_packets
                entry["bytes"] += delta_bytes

            # ----- Per-source ML detection + per-source mitigation -----
            self.detect_flow(
                datapath,
                src,
                dst,
                in_port,
                delta_packets,
                delta_bytes,
                delta_time,
            )

        # ---------------------------------------------------------
        # POST-POLL EVALUATION + MITIGATION
        # Runs once per poll with the complete per-source picture, so it
        # can tell single-source DoS from distributed DDoS and mitigate
        # the right way without the two paths racing.
        # ---------------------------------------------------------
        if MODE == "detect":
            self.evaluate_and_mitigate(
                datapath,
                agg_pkt_rate,
                agg_byte_rate,
                contributions,
            )

            # Dashboard: publish a snapshot of everything just computed.
            self._write_dashboard_state(
                agg_pkt_rate,
                agg_byte_rate,
                contributions,
            )

    # =========================================================
    # WRITE TELEMETRY
    # =========================================================

    def write_telemetry(
        self,
        timestamp,
        dpid,
        src,
        dst,
        in_port,
        packets,
        bytes_,
        duration,
    ):
        try:
            with open(TELEMETRY_PATH, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    dpid,
                    src,
                    dst,
                    in_port,
                    packets,
                    bytes_,
                    duration,
                    LABEL,
                ])
        except Exception as e:
            self.logger.error("Telemetry write error: %s", e)

    # =========================================================
    # ML DETECTION
    # =========================================================

    def detect_flow(
        self,
        datapath,
        src,
        dst,
        in_port,
        packets,
        bytes_,
        duration,
    ):
        if self.model is None:
            return

        duration = max(float(duration), 1e-6)
        packets = max(int(packets), 0)
        bytes_ = max(int(bytes_), 0)

        pkt_rate = packets / duration
        byte_rate = bytes_ / duration
        avg_pkt_size = bytes_ / max(packets, 1)

        if avg_pkt_size > MAX_SANE_AVG_PKT_SIZE:
            self.logger.warning(
                "Ignoring invalid packet size %.2f bytes for %s -> %s",
                avg_pkt_size,
                src,
                dst,
            )
            return

        # IMPORTANT:
        # These are interval/delta features, matching train_model.py.
        X = pd.DataFrame(
            [[
                packets,
                bytes_,
                duration,
                pkt_rate,
                byte_rate,
                avg_pkt_size,
            ]],
            columns=self.feature_cols,
        )

        try:
            prediction_raw = self.model.predict(X)[0]
            prediction = int(prediction_raw)

            probabilities = None
            probability_by_class = {}

            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(X)[0]

                # CRITICAL FIX:
                # predict_proba()[i] corresponds to model.classes_[i],
                # NOT necessarily to label i.
                for index, class_id in enumerate(self.model_classes):
                    if index < len(probabilities):
                        probability_by_class[class_id] = float(
                            probabilities[index]
                        )

            name = self.model_class_names.get(
                prediction,
                CLASS_NAMES.get(prediction, f"UNKNOWN ({prediction})"),
            )

            # -----------------------------------------------------
            # LOG TRAFFIC
            # -----------------------------------------------------

            self.logger.info("")
            self.logger.info("==========================================")
            self.logger.info("TRAFFIC ANALYSIS")
            self.logger.info("src       : %s", src)
            self.logger.info("dst       : %s", dst)
            self.logger.info("packets   : %d", packets)
            self.logger.info("bytes     : %d", bytes_)
            self.logger.info("duration  : %.2f sec", duration)
            self.logger.info("pkt rate  : %.2f pkt/s", pkt_rate)
            self.logger.info("byte rate : %.2f byte/s", byte_rate)
            self.logger.info("avg size  : %.2f bytes", avg_pkt_size)
            self.logger.info("------------------------------------------")

            if probability_by_class:
                self.logger.info("ML CONFIDENCE:")
                
                for class_id in self.model_classes:
                    class_name = self.model_class_names.get(
                        class_id,
                        CLASS_NAMES.get(class_id, f"CLASS-{class_id}")
                    )

                    probability = probability_by_class.get(class_id, 0.0)

                    self.logger.info(
                        "  %-18s %.2f%%",
                        class_name,
                        probability * 100.0
                    )

            self.logger.info("------------------------------------------")
            self.logger.info("FINAL PREDICTION : %s", name)
            self.logger.info("CLASS ID     : %d", prediction)
            self.logger.info("==========================================")

            # -----------------------------------------------------
            # STORE PREDICTION
            # -----------------------------------------------------

            self.write_prediction(
                datapath.id,
                src,
                dst,
                in_port,
                packets,
                bytes_,
                duration,
                pkt_rate,
                byte_rate,
                avg_pkt_size,
                prediction,
                name,
            )

            # Dashboard: remember this source's ML result for this poll.
            self.last_predictions[src] = {
                "prediction": int(prediction),
                "name": name,
                "confidence": {
                    self.model_class_names.get(
                        cid, CLASS_NAMES.get(cid, "CLASS-%d" % cid)
                    ): round(probability_by_class.get(cid, 0.0) * 100.0, 2)
                    for cid in self.model_classes
                },
            }

            # -----------------------------------------------------
            # RESPONSE / OPTIONAL MITIGATION
            # -----------------------------------------------------

            if prediction == 0:

                self.logger.info("🟢 Normal traffic from %s", src)

                # Reset attack counter for this source
                self.attack_counts[src] = 0


            elif prediction == 1:

                self.logger.warning("🟡 Other-malicious traffic from %s", src)

                # Reset attack counter
                self.attack_counts[src] = 0


            elif prediction == 2:

                # Count consecutive per-source flood windows. The BLOCK
                # decision is deliberately NOT made here. It is made once
                # per poll in evaluate_and_mitigate(), AFTER every flow has
                # been seen, so that a simultaneous multi-source flood is
                # confirmed and handled as a DISTRIBUTED DDoS instead of
                # being blocked piecemeal by this per-source path - which
                # would remove the sources from the aggregate pool and
                # starve the distributed detector before it reaches 2/2.
                self.attack_counts[src] = (
                    self.attack_counts.get(src, 0) + 1
                )

                count = self.attack_counts[src]

                self.logger.warning(
                    "⚠️  Per-source flood signature from %s  (window %d/%d)",
                    src,
                    count,
                    self.ATTACK_THRESHOLD,
                )

        except Exception as e:
            self.logger.error(
                "Prediction error for %s -> %s: %s",
                src,
                dst,
                e,
            )

    # =========================================================
    # POST-POLL EVALUATION + MITIGATION (DoS vs DDoS arbiter)
    # =========================================================

    def evaluate_and_mitigate(
        self,
        datapath,
        agg_pkt_rate,
        agg_byte_rate,
        contributions,
    ):
        """
        Runs ONCE per poll, after every flow has been processed, so it
        sees the full picture and can arbitrate between the two attack
        types instead of letting them race:

          * 2+ sources flooding the victim together  -> DISTRIBUTED DDoS.
            Confirmed over 2 consecutive windows, then the contributing
            attackers are blocked. Per-source DoS blocking is SUPPRESSED
            for these windows so it cannot pull sources out of the
            aggregate pool before the aggregate reaches 2/2.

          * exactly 1 source flooding the victim      -> single-source
            DoS. Blocked once its per-source ML counter reaches 2/2.

        The victim is never a source here (it was excluded while building
        the aggregate) and block_source refuses it as a final safeguard.
        """

        n_sources = len(contributions)

        # Nothing headed to the victim this window: reset and stay quiet.
        if n_sources == 0:
            if self.aggregate_attack_count != 0:
                self.aggregate_attack_count = 0
            self.detection_status = "NORMAL"
            return

        # Distinct sources actually FLOODING the victim this window
        # (rate >= the contributor threshold). A stray legitimate packet
        # from another host does not make an attack "distributed".
        active_contributors = {
            mac: c
            for mac, c in contributions.items()
            if c["pkt_rate"] >= CONTRIBUTOR_PKT_RATE_THRESHOLD
        }
        n_contributors = len(active_contributors)

        rate_crossed = (
            agg_pkt_rate >= self.agg_pkt_limit
            or agg_byte_rate >= self.agg_byte_limit
        )

        # DISTRIBUTED requires BOTH: 2+ flooding sources AND the combined
        # rate crosses the threshold. One flooding source is a
        # single-source DoS, never relabelled DDoS.
        is_distributed_ddos = (n_contributors >= 2) and rate_crossed

        # -----------------------------------------------------
        # LOG AGGREGATE VICTIM TRAFFIC (always, for visibility)
        # -----------------------------------------------------
        self.logger.info("")
        self.logger.info("==========================================")
        self.logger.info("📊 AGGREGATE VICTIM TRAFFIC")
        self.logger.info("==========================================")
        self.logger.info("victim            : %s", self.victim_ip)
        self.logger.info("sources -> victim : %d", n_sources)
        self.logger.info(
            "flooding sources  : %d (rate >= %.0f pkt/s)",
            n_contributors,
            CONTRIBUTOR_PKT_RATE_THRESHOLD,
        )
        self.logger.info("agg pkt rate      : %.2f pkt/s", agg_pkt_rate)
        self.logger.info("agg byte rate     : %.2f byte/s", agg_byte_rate)
        self.logger.info(
            "thresholds        : %.0f pkt/s OR %.0f byte/s",
            AGG_PKT_RATE_THRESHOLD,
            AGG_BYTE_RATE_THRESHOLD,
        )
        self.logger.info("------------------------------------------")
        self.logger.info("PER-SOURCE CONTRIBUTION:")
        for mac, c in sorted(
            contributions.items(),
            key=lambda kv: kv[1]["pkt_rate"],
            reverse=True,
        ):
            mac_ip = self.mac_to_ip.get(mac, "?")
            self.logger.info(
                "  %-18s (%-9s) %10.2f pkt/s  %12.2f byte/s",
                mac,
                mac_ip,
                c["pkt_rate"],
                c["byte_rate"],
            )
        self.logger.info("------------------------------------------")

        # =====================================================
        # CASE 1: DISTRIBUTED DDoS (aggregate owns mitigation)
        # =====================================================
        if is_distributed_ddos:
            self.aggregate_attack_count += 1
            count = self.aggregate_attack_count
            self.detection_status = "DDOS"

            self.logger.warning(
                "🚨 DISTRIBUTED DDoS DETECTED (%d flooding sources)  window %d/%d",
                n_contributors,
                count,
                self.ATTACK_THRESHOLD,
            )

            if not (AUTO_MITIGATE and count >= self.ATTACK_THRESHOLD):
                # Confirming - do NOT let the per-source path block yet.
                self.logger.info("==========================================")
                return

            self.logger.warning("")
            self.logger.warning("🚨 DISTRIBUTED DDoS CONFIRMED - blocking contributors")
            for mac, c in sorted(
                active_contributors.items(),
                key=lambda kv: kv[1]["pkt_rate"],
                reverse=True,
            ):
                if mac in self.blocked_macs:
                    continue
                self.logger.warning(
                    "🛡️  Blocked attacker %s (%s) at %.2f pkt/s",
                    mac,
                    self.mac_to_ip.get(mac, "?"),
                    c["pkt_rate"],
                )
                self.block_source(datapath, mac)
                self._add_event(
                    "MITIGATION",
                    "DDoS: blocked %s (%s)"
                    % (mac, self.mac_to_ip.get(mac, "?")),
                )

            self.logger.warning("==========================================")
            return

        # =====================================================
        # CASE 2: NOT DISTRIBUTED -> reset aggregate, then handle
        #         a genuine single-source DoS (per-source ML 2/2).
        # =====================================================
        self.aggregate_attack_count = 0

        # A single-source DoS is a victim-bound source whose per-source ML
        # counter has reached the confirmation threshold. Because we are
        # here, there is at most one flooding source, so this cannot fire
        # during a real distributed attack.
        dos_sources = [
            mac
            for mac in contributions
            if mac not in self.blocked_macs
            and self.attack_counts.get(mac, 0) >= self.ATTACK_THRESHOLD
        ]

        if AUTO_MITIGATE and dos_sources:
            self.detection_status = "DOS"
            for mac in dos_sources:
                self.logger.warning("")
                self.logger.warning(
                    "⚠️  SINGLE-SOURCE DoS CONFIRMED from %s (%s)",
                    mac,
                    self.mac_to_ip.get(mac, "?"),
                )
                self.logger.warning("🛡️  Blocked attacker %s", mac)
                self.block_source(datapath, mac)
                self._add_event(
                    "MITIGATION",
                    "DoS: blocked %s (%s)"
                    % (mac, self.mac_to_ip.get(mac, "?")),
                )
            self.logger.info("==========================================")
            return

        # A DoS label needs an actual flooding source. If the aggregate
        # rate crosses the limit but NO source is individually flooding
        # (n_contributors == 0), it is just many small legitimate flows
        # (e.g. lots of normal users, or a limit set below normal traffic)
        # - that is NORMAL, not an attack. Only exactly one flooding
        # source is a single-source DoS.
        if rate_crossed and n_contributors == 1:
            self.detection_status = "DOS"
            self.logger.info(
                "🟢 AGGREGATE VERDICT : NOT DISTRIBUTED "
                "(1 flooding source -> single-source DoS path)"
            )
        else:
            self.detection_status = "NORMAL"
            if rate_crossed and n_contributors == 0:
                self.logger.info(
                    "🟢 AGGREGATE VERDICT : NORMAL "
                    "(aggregate above limit but no source is flooding)"
                )
            else:
                self.logger.info("🟢 AGGREGATE VERDICT : NORMAL")

        self.logger.info("==========================================")

    # =========================================================
    # DASHBOARD INTEGRATION (additive - never affects detection)
    # =========================================================

    def _refresh_dashboard_control(self):
        """Pick up live threshold overrides set from the dashboard UI."""
        try:
            if not os.path.exists(DASHBOARD_CONTROL_FILE):
                # No overrides -> keep configured defaults.
                self.agg_pkt_limit = AGG_PKT_RATE_THRESHOLD
                self.agg_byte_limit = AGG_BYTE_RATE_THRESHOLD
                self.victim_ip = VICTIM_IP
                return
            with open(DASHBOARD_CONTROL_FILE) as f:
                ctrl = json.load(f)
            pkt = ctrl.get("pkt_rate_limit")
            byt = ctrl.get("byte_rate_limit")
            if isinstance(pkt, (int, float)) and pkt > 0:
                self.agg_pkt_limit = float(pkt)
            if isinstance(byt, (int, float)) and byt > 0:
                self.agg_byte_limit = float(byt)
            vic = ctrl.get("victim_ip")
            if isinstance(vic, str) and vic.strip():
                self.victim_ip = vic.strip()
            else:
                self.victim_ip = VICTIM_IP
        except Exception as e:
            self.logger.debug("dashboard control read skipped: %s", e)

    def _add_event(self, kind, message):
        """Append to the rolling detection/mitigation event log."""
        try:
            self.dashboard_events.append({
                "t": time.time(),
                "type": kind,
                "message": message,
            })
            if len(self.dashboard_events) > DASHBOARD_EVENTS_LEN:
                self.dashboard_events = self.dashboard_events[-DASHBOARD_EVENTS_LEN:]
        except Exception:
            pass

    def _write_dashboard_state(self, agg_pkt_rate, agg_byte_rate, contributions):
        """
        Publish a JSON snapshot of the values THIS poll already produced,
        so the web dashboard shows real experiment data. Fully guarded:
        any failure here must never disturb detection.
        """
        try:
            now = time.time()

            # Running victim totals from this window's victim-bound deltas.
            win_packets = sum(c["packets"] for c in contributions.values())
            win_bytes = sum(c["bytes"] for c in contributions.values())
            self.victim_cumulative_packets += win_packets
            self.victim_cumulative_bytes += win_bytes

            # Per-source rows: merge rate contributions with ML results.
            macs = set(contributions) | set(self.last_predictions)
            sources = []
            for mac in macs:
                c = contributions.get(mac, {})
                pred = self.last_predictions.get(mac, {})
                sources.append({
                    "mac": mac,
                    "ip": self.mac_to_ip.get(mac, "?"),
                    "pkt_rate": round(c.get("pkt_rate", 0.0), 2),
                    "byte_rate": round(c.get("byte_rate", 0.0), 2),
                    "packets": c.get("packets", 0),
                    "bytes": c.get("bytes", 0),
                    "prediction": pred.get("prediction"),
                    "prediction_name": pred.get("name"),
                    "confidence": pred.get("confidence", {}),
                    "blocked": mac in self.blocked_macs,
                })
            sources.sort(key=lambda s: s["pkt_rate"], reverse=True)

            # Rolling rate history for the live chart.
            self.history.append({
                "t": round(now, 2),
                "pkt_rate": round(agg_pkt_rate, 2),
                "byte_rate": round(agg_byte_rate, 2),
            })
            if len(self.history) > DASHBOARD_HISTORY_LEN:
                self.history = self.history[-DASHBOARD_HISTORY_LEN:]

            status = self.detection_status
            under_attack = status in ("DOS", "DDOS")

            blocked = [
                {"mac": m, "ip": self.mac_to_ip.get(m, "?")}
                for m in sorted(self.blocked_macs)
            ]

            state = {
                "timestamp": round(now, 2),
                "poll_interval": POLL_INTERVAL,
                "mode": MODE,
                "detection_status": status,
                "model_classes": self.model_class_names,
                "thresholds": {
                    "pkt_rate_limit": self.agg_pkt_limit,
                    "byte_rate_limit": self.agg_byte_limit,
                    "contributor_pkt_rate": CONTRIBUTOR_PKT_RATE_THRESHOLD,
                    "confirm_windows": self.ATTACK_THRESHOLD,
                },
                "victim": {
                    "ip": self.victim_ip,
                    "status": "UNDER ATTACK" if under_attack else "SAFE",
                    "pkt_rate": round(agg_pkt_rate, 2),
                    "byte_rate": round(agg_byte_rate, 2),
                    "total_packets": self.victim_cumulative_packets,
                    "total_bytes": self.victim_cumulative_bytes,
                },
                "aggregate": {
                    "sources_to_victim": len(contributions),
                    "flooding_sources": sum(
                        1 for c in contributions.values()
                        if c["pkt_rate"] >= CONTRIBUTOR_PKT_RATE_THRESHOLD
                    ),
                    "pkt_rate": round(agg_pkt_rate, 2),
                    "byte_rate": round(agg_byte_rate, 2),
                },
                "sources": sources,
                "blocked": blocked,
                "events": list(reversed(self.dashboard_events)),
                "history": self.history,
            }

            tmp = DASHBOARD_STATE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(state, f)
            os.replace(tmp, DASHBOARD_STATE_FILE)
        except Exception as e:
            self.logger.debug("dashboard state write skipped: %s", e)

    # =========================================================
    # PREDICTION CSV
    # =========================================================

    def write_prediction(
        self,
        dpid,
        src,
        dst,
        in_port,
        packets,
        bytes_,
        duration,
        pkt_rate,
        byte_rate,
        avg_pkt_size,
        prediction,
        name,
    ):
        try:
            with open(PREDICTIONS_PATH, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.time(),
                    dpid,
                    src,
                    dst,
                    in_port,
                    packets,
                    bytes_,
                    duration,
                    pkt_rate,
                    byte_rate,
                    avg_pkt_size,
                    prediction,
                    name,
                ])
        except Exception as e:
            self.logger.error("Prediction CSV error: %s", e)

    # =========================================================
    # PACKET IN
    # =========================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        try:
            in_port = msg.match["in_port"]
        except KeyError:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # Learn MAC -> IP so the monitor can tell attacker from victim.
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt is not None:
            self.mac_to_ip[arp_pkt.src_mac] = arp_pkt.src_ip
        elif ip_pkt is not None:
            self.mac_to_ip[eth.src] = ip_pkt.src

        # Do not install forwarding rules for an already blocked source.
        if src in self.blocked_macs:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst,
            )

            self.add_flow(
                datapath,
                10,
                match,
                actions,
                idle_timeout=60,
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )

        datapath.send_msg(out)

    # =========================================================
    # BLOCK SOURCE
    # =========================================================

    def block_source(self, datapath, src_mac):
        if src_mac in self.blocked_macs:
            return

        # Safety net: never block the protected victim, whatever the
        # classifier says about its reply traffic.
        if self.victim_ip and self.mac_to_ip.get(src_mac) == self.victim_ip:
            self.logger.warning(
                "Refusing to block victim MAC %s (%s)",
                src_mac,
                self.victim_ip,
            )
            return

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac)

        # Empty action list = DROP.
        actions = []

        self.add_flow(
            datapath,
            100,
            match,
            actions,
        )

        self.blocked_macs.add(src_mac)

        self.logger.warning("BLOCKED ATTACKER: %s", src_mac)


# ============================================================
# ENTRY POINT
# ============================================================

# Ryu starts the application through ryu-manager, so no separate
# main() function is required here.