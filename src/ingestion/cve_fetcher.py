from base_fetcher import BaseFetcher


class CVEFetcher(BaseFetcher):

    NVD_URL = (
        "https://nvd.nist.gov/feeds/json/cve/1.1/"
        "nvdcve-1.1-modified.json.zip"
    )

    def fetch(self):

        return self.download_file(
            self.NVD_URL,
            "nvdcve-1.1-modified.json.zip"
        )


if __name__ == "__main__":

    fetcher = CVEFetcher("data/raw/cve")
    fetcher.fetch()
