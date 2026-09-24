import csv
import json
from pathlib import Path
from datetime import datetime
from uuid import UUID

from app.database.postgres import SessionLocal, init_db
from app.models.vulnerability import Vulnerability


def parse_datetime(dt_str: str | None):
    if not dt_str or dt_str.upper() == "NULL" or dt_str == "":
        return None
    try:
        # Replace space with T if needed
        dt_clean = dt_str.replace(" ", "T")
        return datetime.fromisoformat(dt_clean)
    except Exception:
        return None


def parse_json(json_str: str | None):
    if not json_str or json_str.upper() == "NULL" or json_str == "":
        return []
    try:
        return json.loads(json_str)
    except Exception:
        return []


def parse_bool(val: str | None):
    if not val:
        return False
    return val.strip().lower() in ("true", "1", "t", "yes")


def parse_float(val: str | None):
    if not val or val.upper() == "NULL":
        return None
    try:
        return float(val)
    except Exception:
        return None


def load_seed_data(csv_path: str):
    file_path = Path(csv_path)
    if not file_path.exists():
        # Fallback check
        alt_path = file_path.parent / "vuln_seed.csv"
        if alt_path.exists():
            file_path = alt_path
        else:
            raise FileNotFoundError(f"Seed file not found at {csv_path} or {alt_path}")

    print(f"Initializing database tables...")
    init_db()

    print(f"Loading vulnerability seed data from {file_path}...")
    db = SessionLocal()

    inserted = 0
    updated = 0

    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vuln_id = row.get("vulnerability_id")
            source = row.get("source", "UNKNOWN")

            if not vuln_id or not source:
                continue

            existing = db.query(Vulnerability).filter(
                Vulnerability.source == source,
                Vulnerability.vulnerability_id == vuln_id,
            ).first()

            rec_id = row.get("id")
            uuid_val = UUID(rec_id) if rec_id and rec_id.upper() != "NULL" else None

            published_dt = parse_datetime(row.get("published"))
            updated_dt = parse_datetime(row.get("updated"))
            last_seen_dt = parse_datetime(row.get("last_seen_at"))

            if existing is None:
                record = Vulnerability(
                    source=source,
                    vulnerability_id=vuln_id,
                    cve=row.get("cve") if row.get("cve") != "NULL" else None,
                    title=row.get("title") or "",
                    description=row.get("description") or "",
                    vendor=row.get("vendor") if row.get("vendor") != "NULL" else None,
                    product=row.get("product") if row.get("product") != "NULL" else None,
                    affected_versions=parse_json(row.get("affected_versions")),
                    patched_versions=parse_json(row.get("patched_versions")),
                    cpe_matches=parse_json(row.get("cpe_matches")),
                    cvss=parse_float(row.get("cvss")),
                    cvss_vector=row.get("cvss_vector") if row.get("cvss_vector") != "NULL" else None,
                    epss=parse_float(row.get("epss")),
                    kev=parse_bool(row.get("kev")),
                    exploit_available=parse_bool(row.get("exploit_available")),
                    references=parse_json(row.get("references")),
                    published=published_dt,
                    updated=updated_dt,
                    content_hash=row.get("content_hash"),
                    last_seen_at=last_seen_dt,
                    embedding_status=row.get("embedding_status") or "pending",
                )
                if uuid_val:
                    record.id = uuid_val

                db.add(record)
                inserted += 1
            else:
                existing.cve = row.get("cve") if row.get("cve") != "NULL" else None
                existing.title = row.get("title") or ""
                existing.description = row.get("description") or ""
                existing.vendor = row.get("vendor") if row.get("vendor") != "NULL" else None
                existing.product = row.get("product") if row.get("product") != "NULL" else None
                existing.cvss = parse_float(row.get("cvss"))
                existing.epss = parse_float(row.get("epss"))
                existing.kev = parse_bool(row.get("kev"))
                existing.exploit_available = parse_bool(row.get("exploit_available"))
                updated += 1

            if (inserted + updated) % 500 == 0:
                db.commit()
                print(f"Processed {inserted + updated} records...")

        db.commit()
        db.close()

    print(f"Seed loading complete! Inserted: {inserted}, Updated: {updated}")


if __name__ == "__main__":
    # Check default paths
    default_seed = Path("../data/vuln_seed_data.csv")
    if not default_seed.exists():
        default_seed = Path("../data/vuln_seed.csv")
    if not default_seed.exists():
        default_seed = Path("data/vuln_seed_data.csv")

    load_seed_data(str(default_seed))
