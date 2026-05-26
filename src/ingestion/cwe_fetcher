from base_fetcher import BaseFetcher


class CWEFetcher(BaseFetcher):

    CWE_URL = (
        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    )

    def fetch(self):

        return self.download_file(
            self.CWE_URL,
            "cwec_latest.xml.zip"
        )


if __name__ == "__main__":

    fetcher = CWEFetcher("data/raw/cwe")
    fetcher.fetch()
