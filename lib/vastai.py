"""Vast.ai API client — synchronous, minimal, focused on what we need."""

from __future__ import annotations

import json
import time
import httpx
from typing import Optional
from lib.config import VASTAI_API_KEY, VASTAI_BASE_URL


class VastAI:
    """Simple Vast.ai API wrapper."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or VASTAI_API_KEY
        self.base = VASTAI_BASE_URL
        self.client = httpx.Client(timeout=30)
        # Cache for whoami
        self._whoami_cache: dict = {}
        self._whoami_ts: float = 0
        self._whoami_ttl: float = 30  # seconds

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def _params(self, extra: dict | None = None) -> dict:
        p = {"api_key": self.api_key}
        if extra:
            p.update(extra)
        return p

    def _request(self, method: str, url: str, retries: int = 3, **kwargs) -> httpx.Response:
        """HTTP request with automatic retry on 429 rate limit."""
        last_resp = None
        for attempt in range(retries):
            last_resp = getattr(self.client, method)(url, **kwargs)
            if last_resp.status_code == 429:
                wait = min(2 ** attempt * 5, 30)  # 5, 10, 20s
                time.sleep(wait)
                continue
            last_resp.raise_for_status()
            return last_resp
        if last_resp is not None:
            last_resp.raise_for_status()
        raise httpx.HTTPError("Max retries exceeded on 429")

    # ── Account ────────────────────────────────────────────────────────────

    def whoami(self, use_cache: bool = True) -> dict:
        """Get current user info (cached for 30s)."""
        now = time.time()
        if use_cache and self._whoami_cache and (now - self._whoami_ts) < self._whoami_ttl:
            return self._whoami_cache
        r = self._request("get", self._url("/users/current/"), params=self._params())
        self._whoami_cache = r.json()
        self._whoami_ts = now
        return self._whoami_cache

    # ── Instances ──────────────────────────────────────────────────────────

    def get_instances(self) -> list[dict]:
        """List all my instances."""
        r = self._request(
            "get", self._url("/instances/"),
            params=self._params({"owner": "me"}),
        )
        data = r.json()
        return data.get("instances", data) if isinstance(data, dict) else data

    def get_instance(self, instance_id: int) -> dict:
        """Get single instance details."""
        r = self._request(
            "get", self._url(f"/instances/{instance_id}/"),
            params=self._params(),
        )
        data = r.json()
        # API wraps single instance in {"instances": {...}}
        if isinstance(data, dict) and "instances" in data:
            return data["instances"]
        return data

    def get_running_instances(self) -> list[dict]:
        """Get all instances with actual_status == running."""
        instances = self.get_instances()
        return [
            i for i in instances
            if i.get("actual_status") == "running"
            and i.get("ssh_host")
            and i.get("ssh_port")
        ]

    def search_offers(
        self,
        gpu_name: Optional[str] = None,
        num_gpus: int = 1,
        min_dph: float = 0.0,
        max_dph: float = 5.0,
        min_gpu_ram_gb: int = 0,
        min_inet_down: int = 0,
        min_inet_up: int = 0,
        min_disk_gb: int = 0,
        min_cpu_cores: int = 0,
        min_ram_gb: int = 0,
        min_reliability: float = 0.0,
        min_dlperf: float = 0.0,
        cuda_version: float = 0.0,
        verified_only: bool = True,
        order: str = "dph_total",
        limit: int = 20,
    ) -> list[dict]:
        """Search marketplace for GPU offers with extended filters."""
        query = {
            "rentable": {"eq": True},
            "num_gpus": {"gte": num_gpus},
            "dph_total": {"lte": max_dph, "gte": min_dph},
        }
        if verified_only:
            query["verified"] = {"eq": True}
        if gpu_name:
            query["gpu_name"] = {"eq": gpu_name}
        if min_gpu_ram_gb > 0:
            query["gpu_ram"] = {"gte": min_gpu_ram_gb * 1024}
        if min_inet_down > 0:
            query["inet_down"] = {"gte": min_inet_down}
        if min_inet_up > 0:
            query["inet_up"] = {"gte": min_inet_up}
        if min_disk_gb > 0:
            query["disk_space"] = {"gte": min_disk_gb}
        if min_cpu_cores > 0:
            query["cpu_cores_effective"] = {"gte": min_cpu_cores}
        if min_ram_gb > 0:
            query["cpu_ram"] = {"gte": min_ram_gb * 1024}
        if min_reliability > 0:
            query["reliability2"] = {"gte": min_reliability}
        if min_dlperf > 0:
            query["dlperf"] = {"gte": min_dlperf}
        if cuda_version > 0:
            query["cuda_max_good"] = {"gte": cuda_version}

        # Parse order string into Vast.ai format: [["field", "direction"]]
        # Frontend sends: "-dph_total" (desc) or "dph_total" (asc)
        order_list = []
        for part in order.split(","):
            part = part.strip()
            if not part:
                continue
            if part.startswith("-"):
                order_list.append([part[1:], "desc"])
            elif part.endswith("-"):
                order_list.append([part[:-1], "desc"])
            elif part.endswith("+"):
                order_list.append([part[:-1], "asc"])
            else:
                order_list.append([part, "asc"])
        if order_list:
            query["order"] = order_list

        query["type"] = "on-demand"
        query["limit"] = limit

        r = self._request(
            "get", self._url("/bundles/"),
            params=self._params({
                "q": json.dumps(query),
            }),
        )
        data = r.json()
        return data.get("offers", data) if isinstance(data, dict) else data

    def rent_instance(
        self,
        offer_id: int,
        image: str = "vastai/base-image:cuda-12.8.1-auto",
        disk_gb: int = 30,
        onstart_cmd: str = "",
    ) -> dict:
        """Rent a GPU instance."""
        body = {
            "client_id": "me",
            "image": image,
            "disk": disk_gb,
            "runtype": "ssh",
        }
        if onstart_cmd:
            body["onstart"] = onstart_cmd

        r = self._request(
            "put", self._url(f"/asks/{offer_id}/"),
            params=self._params(),
            json=body,
        )
        return r.json()

    def destroy_instance(self, instance_id: int) -> dict:
        """Destroy an instance. Returns empty dict if already gone (404)."""
        try:
            r = self._request(
                "delete", self._url(f"/instances/{instance_id}/"),
                params=self._params(),
            )
            return r.json()
        except Exception as e:
            if "404" in str(e):
                return {"success": True, "already_gone": True}
            raise

    def destroy_instance_verified(self, instance_id: int, retries: int = 3, delay: float = 5.0) -> bool:
        """Destroy an instance and verify it's actually gone. Retry up to `retries` times.
        Returns True if instance is confirmed destroyed/gone."""
        import time as _time
        for attempt in range(1, retries + 1):
            try:
                self.destroy_instance(instance_id)
            except Exception:
                pass
            _time.sleep(delay)
            # Verify it's actually destroyed
            try:
                inst = self.get_instance(instance_id)
                status = inst.get("actual_status", "")
                if status in ("destroyed", "exited", ""):
                    return True
                # Still alive — retry
            except Exception:
                # Instance not found = successfully destroyed
                return True
        return False

    def update_ssh_key(self, ssh_pubkey: str) -> dict:
        """Add SSH public key to Vast.ai account via /ssh/ endpoint."""
        try:
            r = self._request(
                "post", self._url("/ssh/"),
                params=self._params(),
                json={"ssh_key": ssh_pubkey},
            )
            return r.json()
        except Exception as e:
            # 400 with "duplicate" means key already exists — treat as success
            if "duplicate" in str(e).lower() or "already exists" in str(e).lower():
                return {"success": True, "msg": "Key already exists"}
            raise

    def get_ssh_keys(self) -> list[dict]:
        """List all SSH keys from Vast.ai account."""
        r = self._request(
            "get", self._url("/ssh/"),
            params=self._params(),
        )
        return r.json()

    def delete_ssh_key(self, key_id: int) -> dict:
        """Delete an SSH key from Vast.ai account."""
        r = self._request(
            "delete", self._url(f"/ssh/{key_id}/"),
            params=self._params(),
        )
        return r.json()

    def attach_ssh_to_instance(self, instance_id: int, ssh_key: str) -> dict:
        """Attach an SSH key to a specific instance."""
        r = self._request(
            "post", self._url(f"/instances/{instance_id}/ssh/"),
            params=self._params(),
            json={"ssh_key": ssh_key},
        )
        return r.json()

    def get_ssh_key(self) -> str:
        """Get current SSH public keys from Vast.ai account (combined string)."""
        try:
            keys = self.get_ssh_keys()
            if isinstance(keys, list):
                return "\n".join(k.get("public_key", "") for k in keys if k.get("public_key"))
            return ""
        except Exception:
            # Fallback to whoami
            info = self.whoami()
            return info.get("ssh_key", "")


vastai = VastAI()
