from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .report import Reason

REGISTRY_IMAGE_ID_RE = re.compile(
    r"^(?:docker-pullable://)?[^\s/@]+(?:/[^\s/@]+)+@(?P<digest>sha256:[0-9a-f]{64})$"
)
LABEL_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?$")
LABEL_PREFIX_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")


class RuntimeEvidenceError(ValueError):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.message)
        self.reason = reason


@dataclass
class PodObservation:
    uid: str
    name: str
    node: str | None
    container: str
    image: str | None
    image_id: str | None
    container_id: str | None
    ready: bool
    started_at: str | None
    status_present: bool
    phase: str | None
    deletion_timestamp: str | None
    replicaset_uid: str
    replicaset: str
    revision: str | None
    digest_relation: str | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "name": self.name,
            "node": self.node,
            "container": self.container,
            "image": self.image,
            "image_id": self.image_id,
            "container_id": self.container_id,
            "ready": self.ready,
            "phase": self.phase,
            "deletion_timestamp": self.deletion_timestamp,
            "replicaset": self.replicaset,
            "revision": self.revision,
            "digest_relation": self.digest_relation,
            "started_at": self.started_at,
        }

    @property
    def running(self) -> bool:
        return self.phase == "Running" and self.started_at is not None


@dataclass
class RuntimeSnapshot:
    deployment_uid: str
    generation: int
    observed_generation: int | None
    desired: int
    updated: int
    ready: int
    available: int
    revision: str | None
    pods: list[PodObservation] = field(default_factory=list)

    def rollout_reason(self) -> Reason | None:
        if self.desired == 0:
            return Reason("ROLLOUT_INCOMPLETE", "The Deployment requests zero replicas; nonzero replicas are required.")
        if self.observed_generation != self.generation:
            return Reason(
                "ROLLOUT_INCOMPLETE",
                "The Deployment controller has not observed its current generation.",
                self.generation,
                self.observed_generation,
            )
        counts = {"updated": self.updated, "ready": self.ready, "available": self.available}
        if any(value != self.desired for value in counts.values()):
            return Reason(
                "ROLLOUT_INCOMPLETE",
                "Updated, ready, and available replica counts do not all equal desired replicas.",
                self.desired,
                counts,
            )
        if not any(pod.running for pod in self.pods) or any(
            not pod.running or not pod.ready or pod.deletion_timestamp is not None
            for pod in self.pods
        ):
            return Reason(
                "ROLLOUT_INCOMPLETE",
                "At least one owned target container is pending, unready, terminating, or not running.",
            )
        return None

    def stability_fingerprint(self) -> dict[str, Any]:
        return {
            "deployment_uid": self.deployment_uid,
            "generation": self.generation,
            "observed_generation": self.observed_generation,
            "desired": self.desired,
            "updated": self.updated,
            "ready": self.ready,
            "available": self.available,
            "revision": self.revision,
            "pods": [
                {
                    "uid": pod.uid,
                    "container_id": pod.container_id,
                    "image_id": pod.image_id,
                    "ready": pod.ready,
                    "started_at": pod.started_at,
                    "phase": pod.phase,
                    "deletion_timestamp": pod.deletion_timestamp,
                    "replicaset_uid": pod.replicaset_uid,
                    "revision": pod.revision,
                }
                for pod in sorted(self.pods, key=lambda item: (item.uid, item.container))
            ],
        }


def deployment_label_selector(deployment: Any) -> str | None:
    if not isinstance(deployment, dict):
        return None
    spec = _dict(deployment.get("spec"))
    selector = _dict(spec.get("selector"))
    labels = selector.get("matchLabels")
    if not isinstance(labels, dict) or not labels:
        return None
    terms: list[str] = []
    for key, value in labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
        key_parts = key.split("/")
        if len(key_parts) > 2:
            return None
        name = key_parts[-1]
        if not name or len(name) > 63 or not LABEL_NAME_RE.fullmatch(name):
            return None
        if len(key_parts) == 2 and (
            not key_parts[0]
            or len(key_parts[0]) > 253
            or not LABEL_PREFIX_RE.fullmatch(key_parts[0])
        ):
            return None
        if len(value) > 63 or (value and not LABEL_NAME_RE.fullmatch(value)):
            return None
        terms.append(f"{key}={value}")
    return ",".join(sorted(terms))


def build_snapshot(
    deployment: Any,
    replicasets: Any,
    pods: Any,
    container: str,
) -> RuntimeSnapshot:
    if not isinstance(deployment, dict):
        raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "Deployment evidence is not an object."))
    metadata = _dict(deployment.get("metadata"))
    spec = _dict(deployment.get("spec"))
    status = _dict(deployment.get("status"))
    deployment_uid = metadata.get("uid")
    generation = metadata.get("generation")
    if not isinstance(deployment_uid, str) or not deployment_uid or not _positive_int(generation):
        raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "Deployment UID or generation is missing."))
    template_spec = _dict(_dict(spec.get("template")).get("spec"))
    template_containers = template_spec.get("containers")
    if not isinstance(template_containers, list) or not any(
        isinstance(item, dict) and item.get("name") == container for item in template_containers
    ):
        raise RuntimeEvidenceError(
            Reason("CONTAINER_NOT_FOUND", "The named container is absent from the Deployment pod template.", container)
        )

    desired = _nonnegative_int(spec.get("replicas", 1))
    updated = _nonnegative_int(status.get("updatedReplicas", 0))
    ready = _nonnegative_int(status.get("readyReplicas", 0))
    available = _nonnegative_int(status.get("availableReplicas", 0))
    if None in (desired, updated, ready, available):
        raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "Deployment replica counts are missing or invalid."))
    revision = _dict(metadata.get("annotations")).get("deployment.kubernetes.io/revision")
    snapshot = RuntimeSnapshot(
        deployment_uid=deployment_uid,
        generation=generation,
        observed_generation=status.get("observedGeneration"),
        desired=desired,
        updated=updated,
        ready=ready,
        available=available,
        revision=revision if isinstance(revision, str) else None,
    )

    rs_items = replicasets.get("items") if isinstance(replicasets, dict) else None
    pod_items = pods.get("items") if isinstance(pods, dict) else None
    if not isinstance(rs_items, list) or not isinstance(pod_items, list):
        raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "ReplicaSet or Pod list evidence is malformed."))
    owned_rs: dict[str, dict[str, Any]] = {}
    for replicaset in rs_items:
        if not isinstance(replicaset, dict):
            continue
        rs_metadata = _dict(replicaset.get("metadata"))
        uid = rs_metadata.get("uid")
        if isinstance(uid, str) and _owned_by(rs_metadata, deployment_uid):
            owned_rs[uid] = replicaset

    for pod in pod_items:
        if not isinstance(pod, dict):
            continue
        pod_metadata = _dict(pod.get("metadata"))
        rs_uid = _owner_uid(pod_metadata, set(owned_rs))
        if rs_uid is None:
            continue
        pod_spec = _dict(pod.get("spec"))
        pod_status = _dict(pod.get("status"))
        pod_containers = pod_spec.get("containers")
        if not isinstance(pod_containers, list):
            raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "An owned Pod has no container specification."))
        spec_container = next(
            (item for item in pod_containers if isinstance(item, dict) and item.get("name") == container),
            None,
        )
        if spec_container is None:
            raise RuntimeEvidenceError(
                Reason("CONTAINER_NOT_FOUND", "The named container is absent from an owned Pod.", container)
            )
        statuses = pod_status.get("containerStatuses")
        container_status = None
        if isinstance(statuses, list):
            container_status = next(
                (item for item in statuses if isinstance(item, dict) and item.get("name") == container),
                None,
            )
        container_status = _dict(container_status)
        state = _dict(container_status.get("state"))
        running = _dict(state.get("running"))
        rs_metadata = _dict(owned_rs[rs_uid].get("metadata"))
        rs_revision = _dict(rs_metadata.get("annotations")).get("deployment.kubernetes.io/revision")
        pod_uid = pod_metadata.get("uid")
        pod_name = pod_metadata.get("name")
        if not isinstance(pod_uid, str) or not pod_uid or not isinstance(pod_name, str) or not pod_name:
            raise RuntimeEvidenceError(Reason("RUNTIME_EVIDENCE_INVALID", "An owned Pod lacks a UID or name."))
        image_id = container_status.get("imageID")
        container_id = container_status.get("containerID")
        started_at = running.get("startedAt")
        snapshot.pods.append(
            PodObservation(
                uid=pod_uid,
                name=pod_name,
                node=pod_spec.get("nodeName") if isinstance(pod_spec.get("nodeName"), str) else None,
                container=container,
                image=container_status.get("image") or spec_container.get("image"),
                image_id=image_id if isinstance(image_id, str) and image_id else None,
                container_id=container_id if isinstance(container_id, str) and container_id else None,
                ready=container_status.get("ready") is True,
                started_at=started_at if isinstance(started_at, str) and started_at else None,
                status_present=container_status != {},
                phase=pod_status.get("phase") if isinstance(pod_status.get("phase"), str) else None,
                deletion_timestamp=(
                    pod_metadata.get("deletionTimestamp")
                    if isinstance(pod_metadata.get("deletionTimestamp"), str)
                    else None
                ),
                replicaset_uid=rs_uid,
                replicaset=rs_metadata.get("name") or rs_uid,
                revision=rs_revision if isinstance(rs_revision, str) else None,
            )
        )
    snapshot.pods.sort(key=lambda item: (item.uid, item.container))
    return snapshot


def reconcile_runtime_digests(
    snapshot: RuntimeSnapshot,
    attested_digest: str,
    index_children: frozenset[str],
    artifact_is_tag: bool,
) -> Reason | None:
    running = [pod for pod in snapshot.pods if pod.running]
    missing_status = [
        pod for pod in snapshot.pods if pod.phase == "Running" and not pod.status_present
    ]
    if not running and missing_status:
        return Reason(
            "CONTAINER_STATUS_MISSING",
            "Kubernetes reported a running Pod but omitted the named container's status.",
        )
    if not running:
        return Reason(
            "NO_RUNNING_PODS",
            "No running target containers were observed for the Deployment.",
            "at least one running target container" if snapshot.desired else "nonzero desired replicas",
            0,
        )
    unknown: Reason | None = None
    mismatch: Reason | None = None
    if missing_status:
        unknown = Reason(
            "CONTAINER_STATUS_MISSING",
            "At least one running Pod omitted the named container's status.",
        )
    for pod in running:
        if not pod.image_id:
            pod.digest_relation = "unavailable"
            unknown = unknown or Reason(
                "IMAGE_ID_NOT_REGISTRY_COMPARABLE",
                "A running target container has no registry-comparable imageID.",
                actual=None,
            )
            continue
        match = REGISTRY_IMAGE_ID_RE.fullmatch(pod.image_id)
        if not match:
            pod.digest_relation = "not_comparable"
            unknown = unknown or Reason(
                "IMAGE_ID_NOT_REGISTRY_COMPARABLE",
                "A bare local/config image ID or unrecognized imageID cannot prove registry bytes.",
                "repository@sha256:digest",
                pod.image_id,
            )
            continue
        runtime_digest = match.group("digest")
        if runtime_digest == attested_digest:
            pod.digest_relation = "direct"
        elif runtime_digest in index_children:
            pod.digest_relation = "index_child"
        else:
            pod.digest_relation = "mismatch"
            code = "TAG_MOVED" if artifact_is_tag else "RUNTIME_DIGEST_MISMATCH"
            message = (
                "The tag now resolves to an OCI object that does not contain the running image digest."
                if artifact_is_tag
                else "The running image digest is neither the attested digest nor a child of the attested index."
            )
            mismatch = mismatch or Reason(code, message, attested_digest, runtime_digest)
    return mismatch or unknown


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _owned_by(metadata: dict[str, Any], uid: str) -> bool:
    return _owner_uid(metadata, {uid}) is not None


def _owner_uid(metadata: dict[str, Any], candidates: set[str]) -> str | None:
    owners = metadata.get("ownerReferences")
    if not isinstance(owners, list):
        return None
    for owner in owners:
        if isinstance(owner, dict) and owner.get("uid") in candidates:
            return owner["uid"]
    return None


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None
