from sqlalchemy import text

from app.database.postgres import engine


def main():

    windows = [
        ("1999-01-01", "1999-04-30"),
        ("1999-04-30", "1999-08-27"),
        ("1999-08-27", "1999-12-24"),
        ("1999-12-24", "2000-04-21"),
        ("2000-04-21", "2000-08-18"),
        ("2000-08-18", "2000-12-15"),
        ("2000-12-15", "2001-04-13"),
    ]

    with engine.connect() as conn:

        print("=" * 80)
        print("NVD DATA BY WINDOW")
        print("=" * 80)

        for start, end in windows:

            count = conn.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM vulnerabilities
                    WHERE source = 'nvd'
                      AND published >= :start
                      AND published <= :end
                    """
                ),
                {
                    "start": start,
                    "end": end,
                },
            ).scalar()

            print(
                f"{start} → {end}: "
                f"{count} vulnerabilities"
            )


if __name__ == "__main__":
    main()