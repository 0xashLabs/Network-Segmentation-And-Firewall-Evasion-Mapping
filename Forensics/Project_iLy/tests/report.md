# Project iLy - Incident Attribution Report

| Metadata Parameter | Value |
|---|---|
| **Report ID** | `attr_1785210977` |
| **Incident ID** | `timeline_1785210977` |
| **Attribution Version** | `v1.0.0` |
| **Generated At** | `1785210977` (Unix Epoch) |
| **Alignment Method** | `tolerance_band_fallback` |
| **Time Window** | 999.500000s to 1000.200000s (Duration: 0.7000s) |

## 1. Input Files Integrity & Chain of Custody

The following cryptographic hashes verify the authenticity of the parsed inputs:

| Filename | MD5 Hash | SHA-256 Hash |
|---|---|---|
| `test_can.json` | `685eea0586c44c3ef973a955ba3e4a82` | `1e00f448e8d76ec45342275f9aff4e6a0dedc74cdc67ff1a8f2de44c30d70c5f` |
| `test_cdr.csv` | `d35ab02c97b5a4c28293b5b0147f8a05` | `665fe069bcd5ba3a46a8be48999fcf546619c47112303a04c8fc0b7f7272c07e` |

## 2. Executive Summary

> [!IMPORTANT]
> **PRIMARY ATTRIBUTION FACTOR**: **CYBER**
> 
> **Confidence**: **85.02%**
> **Corroboration Tier**: **high**

## 3. Policy & Score Breakdown

| Category | Normalized Score | Corroboration Tier | Active IoCs / Policies Triggers |
|---|---|---|---|
| cyber | **0.8501** | high | `IOC_CYBER_02`, `IOC_CYBER_01` |
| environmental | **0.0000** | low | *None* |
| mechanical | **0.6650** | low | `IOC_MECH_01` |
| software | **0.5950** | low | `IOC_SOFT_02` |

## 4. Narrative Timeline

Chronological sequence of reconciled and normalized events across inputs:

| Index | Original Timestamp | Adjusted Timestamp | Source | Event Narrative / Payload | Time Confidence |
|---|---|---|---|---|---|
| 0 | 999.500000s | 999.500000s | `can_log` (test_can.json) | **CAN Frame**: ID 0x300 [DLC 1] data: 03 <span style='color:orange;'>[INJECTION ANOMALY]</span> <span style='color:red;'>[DIAG SESSION ACTIVE]</span>  | medium |
| 1 | 1000.000000s | 1000.000000s | `bosch_cdr` (test_cdr.csv) | **EDR Snapshot**: Speed = 45 mph, Delta-V = 42 mph, Brakes = ON, RPM = 3000 <span style='color:red;'>[BRAKE STATUS CONFLICT]</span> | medium |
| 2 | 1000.200000s | 1000.200000s | `can_log` (test_can.json) | **CAN Frame**: ID 0x200 [DLC 1] data: 00  | medium |

## 5. Audit Trail & Raw Reference Logs

Detailed reference to files and logs triggers:

* **Event ID**: `can_2` | **File**: `tests/test_can.json` | **Ref**: `Index 1`
  * *Raw Image Metadata*: `None`
* **Event ID**: `cdr_1` | **File**: `tests/test_cdr.csv` | **Ref**: `Line 2`
  * *Raw Image Metadata*: `None`

## 6. Confidence Notes & Expert Guidance

* **Corroboration Tier Mapping**:
  * **High**: Matches observed across multiple independent digital sources (e.g., EDR cross-checked with CAN traffic) confirming the incident vector.
  * **Medium**: Indicators present in a single source with high confidence but lacking direct hardware/cross-file confirmation.
  * **Low**: Low confidence scores or weak timeline alignment with high discrepancy bounds.
* **Forensic Notice**: This report serves as an investigation assistant to organize incident timeline evidence and flag anomaly indicators. Results must be verified by a certified vehicle forensics specialist.
