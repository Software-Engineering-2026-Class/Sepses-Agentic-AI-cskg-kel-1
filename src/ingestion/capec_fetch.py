from base_fetcher import BaseFetcher


class CAPECFetcher(BaseFetcher):

    CAPEC_URL = (
        "https://capec.mitre.org/data/xml/capec_latest.xml"
    )

    def fetch(self):

        return self.download_file(
            self.CAPEC_URL,
            "capec_latest.xml"
        )


if __name__ == "__main__":

    fetcher = CAPECFetcher("data/raw/capec")
    fetcher.fetch()
