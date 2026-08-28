from datetime import datetime


class CISAKEVNormalizer:

    def normalize(self, record):

        cve = record.get(
            "cveID"
        )

        return {
            "cve": cve,

            "vendor":
                record.get(
                    "vendorProject"
                ),

            "product":
                record.get(
                    "product"
                ),

            "vulnerability_name":
                record.get(
                    "vulnerabilityName"
                ),

            "short_description":
                record.get(
                    "shortDescription"
                ),

            "required_action":
                record.get(
                    "requiredAction"
                ),

            "due_date":
                record.get(
                    "dueDate"
                ),

            "known_ransomware":
                record.get(
                    "knownRansomwareCampaignUse"
                ),
        }