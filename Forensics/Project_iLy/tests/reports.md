# Project iLy - Incident Attribution Report

| Metadata Parameter | Value |
|---|---|
| **Report ID** | `attr_1785261569` |
| **Incident ID** | `timeline_1785261569` |
| **Attribution Version** | `v1.0.0` |
| **Generated At** | `1785261569` (Unix Epoch) |
| **Alignment Method** | `tolerance_band_fallback` |
| **Time Window** | 999.500000s to 1000.200000s (Duration: 0.7000s) |

## 1. Input Files Integrity & Chain of Custody

The following cryptographic hashes verify the authenticity of the parsed inputs:

| Filename | MD5 Hash | SHA-256 Hash |
|---|---|---|
| `test_can.json` | `685eea0586c44c3ef973a955ba3e4a82` | `1e00f448e8d76ec45342275f9aff4e6a0dedc74cdc67ff1a8f2de44c30d70c5f` |
| `tests_cdr.csv` | `FILE_NOT_FOUND` | `FILE_NOT_FOUND` |

## 2. Executive Summary

> [!IMPORTANT]
> **PRIMARY ATTRIBUTION FACTOR**: **CYBER**
> 
> **Confidence**: **36.00%**
> **Corroboration Tier**: **low**

## 3. Policy & Score Breakdown

| Category | Normalized Score | Corroboration Tier | Active IoCs / Policies Triggers |
|---|---|---|---|
| cyber | **0.3600** | low | `IOC_CYBER_02` |
| environmental | **0.0000** | low | *None* |
| mechanical | **0.0000** | low | *None* |
| software | **0.3400** | low | `IOC_SOFT_02` |

## 4. Narrative Timeline

Chronological sequence of reconciled and normalized events across inputs:

| Index | Original Timestamp | Adjusted Timestamp | Source | Event Narrative / Payload | Time Confidence |
|---|---|---|---|---|---|
| 0 | 999.500000s | 999.500000s | `can_log` (test_can.json) | **CAN Frame**: ID 0x300 [DLC 1] data: 03 <span style='color:orange;'>[INJECTION ANOMALY]</span> <span style='color:red;'>[DIAG SESSION ACTIVE]</span>  | low |
| 1 | 1000.200000s | 1000.200000s | `can_log` (test_can.json) | **CAN Frame**: ID 0x200 [DLC 1] data: 00  | low |

## 5. Audit Trail & Raw Reference Logs

Detailed reference to files and logs triggers:

* **Event ID**: `can_2` | **File**: `tests/test_can.json` | **Ref**: `Index 1`
  * *Raw Image Metadata*: `None`

## 6. Confidence Notes & Expert Guidance

* **Corroboration Tier Mapping**:
  * **High**: Matches observed across multiple independent digital sources (e.g., EDR cross-checked with CAN traffic) confirming the incident vector.
  * **Medium**: Indicators present in a single source with high confidence but lacking direct hardware/cross-file confirmation.
  * **Low**: Low confidence scores or weak timeline alignment with high discrepancy bounds.
* **Forensic Notice**: This report serves as an investigation assistant to organize incident timeline evidence and flag anomaly indicators. Results must be verified by a certified vehicle forensics specialist.
