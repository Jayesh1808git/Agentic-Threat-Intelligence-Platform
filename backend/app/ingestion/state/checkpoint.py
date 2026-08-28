import json
from pathlib import Path


class Checkpoint:

    def __init__(
        self,
        path="data/ingestion_checkpoint.json",
    ):

        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state = self.load()

    def load(self):

        if not self.path.exists():
            return {
                "nvd_completed": [],
                "osv_completed": False,
                "github_completed": False,
                "cisa_completed": False,
                "epss_completed": False,
            }

        try:

            return json.loads(
                self.path.read_text()
            )

        except Exception:

            return {
                "nvd_completed": [],
                "osv_completed": False,
                "github_completed": False,
                "cisa_completed": False,
                "epss_completed": False,
            }

    def save(self):

        tmp = self.path.with_suffix(
            ".tmp"
        )

        tmp.write_text(
            json.dumps(
                self.state,
                indent=2,
            )
        )

        tmp.replace(self.path)

    def nvd_done(
        self,
        window,
    ):

        return (
            window
            in self.state["nvd_completed"]
        )

    def mark_nvd_done(
        self,
        window,
    ):

        if not self.nvd_done(window):

            self.state[
                "nvd_completed"
            ].append(window)

            self.save()