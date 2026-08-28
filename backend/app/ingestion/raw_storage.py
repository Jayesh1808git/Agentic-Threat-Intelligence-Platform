from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class RawStorage:

    def __init__(
        self,
        base_dir: str = "./data/raw",
    ):
        self.base_dir = Path(base_dir)

        self.base_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save(
        self,
        source: str,
        records: list[dict[str, Any]],
    ) -> Path:

        timestamp = datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )

        source_dir = (
            self.base_dir / source.lower()
        )

        source_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            source_dir
            / f"{timestamp}.jsonl"
        )

        with path.open(
            "w",
            encoding="utf-8",
        ) as f:

            for record in records:

                f.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        default=str,
                    )
                )

                f.write("\n")

        return path