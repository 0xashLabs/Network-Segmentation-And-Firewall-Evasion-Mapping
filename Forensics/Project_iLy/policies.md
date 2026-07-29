# Project iLy - Policy Registry (v1)

This registry defines the Indicators of Compromise (IoC) used by the Project iLy attribution engine to evaluate incidents.
The engine parses this file at runtime to apply safety/policy rules.

| ioc_id | category | match_type | trigger_field | operator | trigger_value | description | match_confidence |
|---|---|---|---|---|---|---|---|
| IOC_CYBER_01 | cyber | pattern | brake_status_conflict | equals | true | Contradictory brake status between CAN logs and EDR | 0.85 |
| IOC_CYBER_02 | cyber | pattern | packet_injection | equals | true | High rate of unexpected CAN arbitration IDs | 0.90 |
| IOC_MECH_01 | mechanical | heuristic | delta_v | greater_than | 40.0 | High energy impact detected | 0.95 |
| IOC_MECH_02 | mechanical | heuristic | brake_pressure_low | equals | true | Hydraulic pressure below nominal braking threshold | 0.80 |
| IOC_SOFT_01 | software | exact | firmware_error_flag | equals | true | ECU software firmware validation failure | 0.95 |
| IOC_SOFT_02 | software | exact | diagnostic_mode_active | equals | true | ECU placed in diagnostic session during motion | 0.85 |
| IOC_ENV_01 | environmental | heuristic | traction_loss | equals | true | Stability control reports continuous slip | 0.75 |
