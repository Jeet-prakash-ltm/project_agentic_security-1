class BackupConfigurationCollector:

    def __init__(self, firewall):
        self.firewall = firewall

    def collect(self):

        result = {
            "scheduled_backups": False,
            "versioned_configs": False,
            "last_backup": None,
            "restore_tested": None
        }

        try:

            jobs = self.firewall.op(
                "show jobs all",
                xml=False
            )

            output = str(jobs)
            result["job_output"] = output[:2000]
            lowered = output.lower()
            if "commit" in lowered or "save" in lowered or "export" in lowered:
                result["versioned_configs"] = True
            if "scheduled" in lowered or "export configuration" in lowered:
                result["scheduled_backups"] = True

        except Exception as e:

            result["error"] = str(e)

        return result