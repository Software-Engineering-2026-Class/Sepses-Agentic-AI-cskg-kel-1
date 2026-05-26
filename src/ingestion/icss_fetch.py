from base_fetcher import BaseFetcher


class ICSAFetcher(BaseFetcher):

    ICSA_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "ics_advisories.json"
    )

    def fetch(self):

        return self.download_file(
            self.ICSA_URL,
            "ics_advisories.json"
        )


if __name__ == "__main__":

    fetcher = ICSAFetcher("data/raw/icsa")
    fetcher.fetch()
