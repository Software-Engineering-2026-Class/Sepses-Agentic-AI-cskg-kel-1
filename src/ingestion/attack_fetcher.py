from base_fetcher import BaseFetcher


class AttackFetcher(BaseFetcher):

    ATTACK_URL = (
        "https://raw.githubusercontent.com/"
        "mitre/cti/master/enterprise-attack/"
        "enterprise-attack.json"
    )

    def fetch(self):

        return self.download_file(
            self.ATTACK_URL,
            "enterprise-attack.json"
        )


if __name__ == "__main__":

    fetcher = AttackFetcher("data/raw/attack")
    fetcher.fetch()
