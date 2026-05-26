from base_fetcher import BaseFetcher


class CPEFetcher(BaseFetcher):

    CPE_URL = (
        "https://nvd.nist.gov/feeds/json/cpematch/1.0/"
        "nvdcpematch-1.0.json.zip"
    )

    def fetch(self):

        return self.download_file(
            self.CPE_URL,
            "nvdcpematch-1.0.json.zip"
        )


if __name__ == "__main__":

    fetcher = CPEFetcher("data/raw/cpe")
    fetcher.fetch()
