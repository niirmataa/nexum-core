# NXMS Maintenance Artifact Model

To jest kontrakt logiczny dla `maintenance artifact` używanego przez `GDA-5`.

Nie opisuje jeszcze finalnego wire formatu.
Zamraża:
- do czego maintenance artifact służy,
- jakie ma pola logiczne,
- czego nie wolno nim robić,
- kiedy ma być odrzucany fail-closed.

## 1. Cel

`maintenance artifact` daje bardzo wąskie, krótkotrwałe uprawnienie serwisowe.

Nie jest to artefakt trust-changing.
Nie jest to artefakt aktywacyjny.
Nie jest to artefakt recovery.

Służy wyłącznie do operacji klasy `B`.

## 2. Zasady ogólne

Maintenance artifact:
- ma bardzo krótki TTL,
- jest przypięty do konkretnego hosta,
- jest przypięty do konkretnej roli,
- jest przypięty do konkretnej akcji,
- jest wystawiany tylko przez guardy,
- nie może zmieniać trust root systemu,
- nie może zastępować `GDA-2` ani `GDA-3`.

## 3. Zakres operacji

Dozwolone typy operacji na start:
- `restart_service`,
- `replace_binary`,
- `rollout_config`,
- `host_rejoin_same_identity`.

Niedozwolone:
- aktywacja systemu,
- resurrection,
- relokacja,
- trust-set rotation,
- guard root key rotation,
- `sign`,
- `submit`,
- finalne `release/refund/close/fail`.

Jeśli dana operacja przekracza maintenance scope, wpada do `GDA-3`.

## 4. Format logiczny

Minimalny kontrakt logiczny:

```json
{
  "artifact_type": "gda_maintenance_v1",
  "artifact_id": "opaque-id",
  "system_epoch": 12,
  "guard_set_epoch": 4,
  "operation_class": "B",
  "maintenance_kind": "restart_service",
  "target_role": "nxms-signer",
  "target_host_id": "signer-host-02",
  "target_service": "nxms-signer",
  "target_binary_path": "/opt/nxms/bin/nxms-signer",
  "scope": {
    "allowed_actions": ["restart_service"],
    "service_names": ["nxms-signer"],
    "config_paths": [],
    "binary_paths": []
  },
  "state_precondition": {
    "host_sealed_state_hash": "hex-or-null",
    "expected_config_hash": "hex-or-null",
    "expected_binary_hash": "hex-or-null"
  },
  "issued_at": "2026-03-11T10:00:00Z",
  "not_before": "2026-03-11T10:00:00Z",
  "not_after": "2026-03-11T10:15:00Z",
  "operator_ref": "opaque-operator-id",
  "reason_code": "planned_restart",
  "ticket_ref": "opaque-ticket",
  "revoke_ref": "revset-ref",
  "cutover_ref": "cutover-ref",
  "falcon_signatures": [
    {"guard_id": "guard-2", "sig": "base64"},
    {"guard_id": "guard-4", "sig": "base64"}
  ]
}
```

## 5. Pola obowiązkowe

Każdy maintenance artifact musi mieć:
- `artifact_type`,
- `artifact_id`,
- `system_epoch`,
- `guard_set_epoch`,
- `operation_class`,
- `maintenance_kind`,
- `target_role`,
- `target_host_id`,
- `scope`,
- `not_before`,
- `not_after`,
- `revoke_ref`,
- `cutover_ref`,
- `falcon_signatures`.

## 6. Pola warunkowe

### `restart_service`

Wymaga:
- `target_service`,
- `target_host_id`,
- `target_role`.

Opcjonalnie:
- `host_sealed_state_hash`.

### `replace_binary`

Wymaga:
- `target_binary_path`,
- `expected_binary_hash`,
- `approved_new_binary_hash` albo równoważnej referencji zatwierdzonej binarki.

### `rollout_config`

Wymaga:
- `config_paths`,
- `expected_config_hash`,
- `approved_new_config_hash` albo równoważnej referencji zatwierdzonej konfiguracji.

### `host_rejoin_same_identity`

Wymaga:
- zachowania tej samej tożsamości hosta,
- zgodnego sealed state,
- braku zmiany trust setu.

Jeśli zmienia się tożsamość hosta albo sealed state nie jest zaufany, nie jest to maintenance. To jest `GDA-3`.

## 7. Weryfikacja

Maintenance artifact jest weryfikowany przez host runtime preflight.

Host musi sprawdzić:
- podpisy `Falcon`,
- `system_epoch`,
- `guard_set_epoch`,
- `target_host_id`,
- `target_role`,
- `maintenance_kind`,
- `scope`,
- `TTL`,
- `revoke_ref`,
- `cutover_ref`,
- zgodność `state_precondition`, jeśli występuje.

## 8. Fail-closed odrzucenie

Artifact musi być odrzucony przy:
- `system_epoch` mismatch,
- `guard_set_epoch` mismatch,
- revoke,
- cutover mismatch,
- host mismatch,
- role mismatch,
- action mismatch,
- scope mismatch,
- TTL expiry,
- drift `sealed_state_hash`,
- drift configu albo binarki poza zatwierdzonym zakresem.

Odrzucenie musi kończyć się:
- brakiem wykonania operacji,
- wpisem do audytu,
- opcjonalnym `quarantine`, jeśli naruszenie wygląda na manipulację.

## 9. Czego nie wolno robić

Maintenance artifact nie może:
- aktywować systemu,
- reaktywować systemu,
- robić resurrection,
- zmieniać trust setu,
- rotować guard root keys,
- autoryzować `sign`,
- autoryzować `submit`,
- zastępować `GDA-2`,
- zastępować `GDA-3`.

## 10. Profile startowe

Na start NXMS zamraża trzy profile:
- `maintenance_restart_v1`,
- `maintenance_binary_rollout_v1`,
- `maintenance_config_rollout_v1`.

Nie wprowadzamy na tym etapie ogólnego „super-artifact” maintenance.
